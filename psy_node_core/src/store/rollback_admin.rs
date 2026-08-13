//! Edge-facing, typed handoff into the durable rollback admission inbox.
//!
//! This is deliberately smaller than the rollback control plane.  A queued
//! command is not an active rollback: only the Coordinator Processor may
//! consume the inbox and publish `REQUESTED` in the canonical-head row.

use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::{CanonicalChainRef, CheckpointRef, NetworkId};
use tokio::sync::Mutex;

use super::{
    canonical_head::{
        CanonicalHeadReadState, CanonicalHeadRevision, CoordinatorCanonicalHeadReader,
        StoredCanonicalHead,
    },
    rollback_admission::{
        CoordinatorRollbackAdmissionStore, RollbackAdmissionCommand,
        RollbackAdmissionSlotRevision,
        RollbackAdmissionSlotReadState, RollbackAdmissionSlotState,
        RollbackAdmissionSlotWriteOutcome, SealedRollbackAdmissionSlotCas,
        StoredRollbackAdmissionSlot,
    },
    rollback_control::{RollbackExecutionMode, RollbackPlanDigest, RollbackRequest},
    rollback_participant_plan::{
        CoordinatorRollbackParticipantPlanStore, RollbackParticipantPlan,
    },
    timestamp::TimestampFenceWindow,
};

/// Explicit operator gate.  The default configuration maps to `Disabled`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackAdminInboxAccess {
    Disabled,
    ManualPreflight,
}

/// A request whose field meanings are already typed, but which has not yet
/// been matched against the durable canonical head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackAdminStartIntent<Hash> {
    expected_revision: CanonicalHeadRevision,
    expected_canonical_ref: CanonicalChainRef<Hash>,
    target: CheckpointRef<Hash>,
    fence_window: TimestampFenceWindow,
    execution_mode: RollbackExecutionMode,
    plan_digest: RollbackPlanDigest,
}

/// Public admin handoff before the server selects and persists the current
/// deployment topology.  It carries no caller-supplied plan digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackAdminPlannedStartIntent<Hash> {
    expected_revision: CanonicalHeadRevision,
    expected_canonical_ref: CanonicalChainRef<Hash>,
    target: CheckpointRef<Hash>,
    fence_window: TimestampFenceWindow,
    topology_revision: u64,
    topology_digest: [u8; 32],
}

impl<Hash> RollbackAdminPlannedStartIntent<Hash> {
    pub const fn new(
        expected_revision: CanonicalHeadRevision,
        expected_canonical_ref: CanonicalChainRef<Hash>,
        target: CheckpointRef<Hash>,
        fence_window: TimestampFenceWindow,
        topology_revision: u64,
        topology_digest: [u8; 32],
    ) -> Self {
        Self {
            expected_revision,
            expected_canonical_ref,
            target,
            fence_window,
            topology_revision,
            topology_digest,
        }
    }

    pub const fn expected_revision(&self) -> CanonicalHeadRevision {
        self.expected_revision
    }

    pub const fn target(&self) -> &CheckpointRef<Hash> {
        &self.target
    }

    pub const fn fence_window(&self) -> TimestampFenceWindow {
        self.fence_window
    }

    pub const fn topology_revision(&self) -> u64 {
        self.topology_revision
    }

    pub const fn topology_digest(&self) -> &[u8; 32] {
        &self.topology_digest
    }
}

impl<Hash> RollbackAdminStartIntent<Hash> {
    pub const fn new(
        expected_revision: CanonicalHeadRevision,
        expected_canonical_ref: CanonicalChainRef<Hash>,
        target: CheckpointRef<Hash>,
        fence_window: TimestampFenceWindow,
        execution_mode: RollbackExecutionMode,
        plan_digest: RollbackPlanDigest,
    ) -> Self {
        Self {
            expected_revision,
            expected_canonical_ref,
            target,
            fence_window,
            execution_mode,
            plan_digest,
        }
    }

    pub const fn expected_revision(&self) -> CanonicalHeadRevision {
        self.expected_revision
    }

    pub const fn expected_canonical_ref(&self) -> &CanonicalChainRef<Hash> {
        &self.expected_canonical_ref
    }

    pub const fn target(&self) -> &CheckpointRef<Hash> {
        &self.target
    }

    pub const fn fence_window(&self) -> TimestampFenceWindow {
        self.fence_window
    }

    pub const fn execution_mode(&self) -> RollbackExecutionMode {
        self.execution_mode
    }

    pub const fn plan_digest(&self) -> RollbackPlanDigest {
        self.plan_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackAdminInboxPhase {
    Idle,
    Pending,
    Active,
    Stale,
}

impl RollbackAdminInboxPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "IDLE",
            Self::Pending => "PENDING",
            Self::Active => "ACTIVE",
            Self::Stale => "STALE",
        }
    }
}

/// Stable rejection returned by the Coordinator Edge maintenance gate.
///
/// `Pending` is intentionally blocking even before the Processor promotes the
/// command to authoritative rollback control. `Stale` is also blocking: an
/// operator must reconcile the durable inbox instead of silently admitting
/// new work against an ambiguous observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackMaintenanceGateError {
    phase: RollbackAdminInboxPhase,
}

impl fmt::Display for RollbackMaintenanceGateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ROLLBACK_IN_PROGRESS:{}", self.phase.as_str())
    }
}

impl std::error::Error for RollbackMaintenanceGateError {}

impl RollbackMaintenanceGateError {
    const fn new(phase: RollbackAdminInboxPhase) -> Self {
        Self { phase }
    }

    pub const fn phase(&self) -> RollbackAdminInboxPhase {
        self.phase
    }
}

/// Read-only evidence that the canonical head and rollback inbox were stable
/// and idle at one admission boundary.
///
/// This is deliberately not a lease: C-02's epoch-carrying messages are still
/// required to close the race between this check and a later cross-store side
/// effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackMaintenancePermit<Hash> {
    canonical_head: StoredCanonicalHead<Hash>,
    inbox_revision: RollbackAdmissionSlotRevision,
}

impl<Hash> RollbackMaintenancePermit<Hash> {
    pub const fn canonical_head(&self) -> &StoredCanonicalHead<Hash> {
        &self.canonical_head
    }

    pub const fn inbox_revision(&self) -> RollbackAdmissionSlotRevision {
        self.inbox_revision
    }
}

const MAINTENANCE_GATE_CACHE_TTL: Duration = Duration::from_millis(100);

#[derive(Clone, Debug)]
enum CachedRollbackMaintenanceState<Hash> {
    Available(RollbackMaintenancePermit<Hash>),
    Blocked(RollbackAdminInboxPhase),
    Unavailable(String),
}

impl<Hash: Copy> CachedRollbackMaintenanceState<Hash> {
    fn result(&self) -> anyhow::Result<RollbackMaintenancePermit<Hash>> {
        match self {
            Self::Available(permit) => Ok(*permit),
            Self::Blocked(phase) => Err(RollbackMaintenanceGateError::new(*phase).into()),
            Self::Unavailable(error) => anyhow::bail!(error.clone()),
        }
    }
}

#[derive(Clone, Debug)]
struct CachedRollbackMaintenanceObservation<Hash> {
    observed_at: Instant,
    state: CachedRollbackMaintenanceState<Hash>,
}

/// A two-row observation.  The rows are individually atomic but are not a
/// cross-table snapshot; consumers must use `phase`, not infer authority from
/// the inbox alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackAdminInboxStatus<Hash> {
    canonical_head: StoredCanonicalHead<Hash>,
    admission_slot: StoredRollbackAdmissionSlot<Hash>,
    phase: RollbackAdminInboxPhase,
}

impl<Hash> RollbackAdminInboxStatus<Hash> {
    pub const fn canonical_head(&self) -> &StoredCanonicalHead<Hash> {
        &self.canonical_head
    }

    pub const fn admission_slot(&self) -> &StoredRollbackAdmissionSlot<Hash> {
        &self.admission_slot
    }

    pub const fn phase(&self) -> RollbackAdminInboxPhase {
        self.phase
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackAdminStartDisposition {
    Accepted,
    Idempotent,
    Disabled,
    AlreadyActive,
    HeadMismatch,
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RollbackAdminStartReceipt<Hash> {
    disposition: RollbackAdminStartDisposition,
    status: RollbackAdminInboxStatus<Hash>,
}

impl<Hash> RollbackAdminStartReceipt<Hash> {
    pub const fn disposition(&self) -> RollbackAdminStartDisposition {
        self.disposition
    }

    pub const fn status(&self) -> &RollbackAdminInboxStatus<Hash> {
        &self.status
    }
}

/// Edge capability: read the canonical head and offer one command to the
/// inbox.  It intentionally has no canonical-head writer.
pub struct CoordinatorRollbackAdminInbox<Hash> {
    network: NetworkId,
    access: RollbackAdminInboxAccess,
    canonical_head_reader: Arc<dyn CoordinatorCanonicalHeadReader<Hash>>,
    admission_store: Arc<dyn CoordinatorRollbackAdmissionStore<Hash>>,
    participant_plan_store:
        Option<Arc<dyn CoordinatorRollbackParticipantPlanStore<Hash>>>,
    maintenance_cache: Mutex<Option<CachedRollbackMaintenanceObservation<Hash>>>,
}

impl<Hash> CoordinatorRollbackAdminInbox<Hash> {
    pub fn new(
        network: NetworkId,
        access: RollbackAdminInboxAccess,
        canonical_head_reader: Arc<dyn CoordinatorCanonicalHeadReader<Hash>>,
        admission_store: Arc<dyn CoordinatorRollbackAdmissionStore<Hash>>,
    ) -> Self {
        Self {
            network,
            access,
            canonical_head_reader,
            admission_store,
            participant_plan_store: None,
            maintenance_cache: Mutex::new(None),
        }
    }

    pub fn with_participant_plan_store(
        mut self,
        store: Arc<dyn CoordinatorRollbackParticipantPlanStore<Hash>>,
    ) -> Self {
        self.participant_plan_store = Some(store);
        self
    }

    pub const fn access(&self) -> RollbackAdminInboxAccess {
        self.access
    }
}

impl<Hash: Q256BitHash + Send + Sync + 'static> CoordinatorRollbackAdminInbox<Hash> {
    /// Production explicit-start path.  The current durable topology selects
    /// the complete Realm list; the immutable plan is exact-read before the
    /// admission inbox can become pending.
    pub async fn start_planned(
        &self,
        intent: RollbackAdminPlannedStartIntent<Hash>,
    ) -> anyhow::Result<RollbackAdminStartReceipt<Hash>> {
        let observed = self.status().await?;
        if self.access == RollbackAdminInboxAccess::Disabled {
            return Ok(receipt(RollbackAdminStartDisposition::Disabled, observed));
        }
        if !observed.canonical_head.rollback_control().is_idle() {
            return Ok(receipt(
                RollbackAdminStartDisposition::AlreadyActive,
                observed,
            ));
        }
        if observed.canonical_head.revision() != intent.expected_revision
            || observed.canonical_head.canonical_ref() != &intent.expected_canonical_ref
        {
            return Ok(receipt(
                RollbackAdminStartDisposition::HeadMismatch,
                observed,
            ));
        }
        let store = self
            .participant_plan_store
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("ROLLBACK_PARTICIPANT_PLAN_STORE_NOT_INSTALLED"))?;
        let topology = store
            .read_current_rollback_topology(self.network)
            .await?
            .ok_or_else(|| anyhow::anyhow!("ROLLBACK_TOPOLOGY_UNINITIALIZED"))?;
        if topology.revision() != intent.topology_revision
            || topology.digest() != &intent.topology_digest
        {
            anyhow::bail!("ROLLBACK_TOPOLOGY_EXPECTATION_MISMATCH");
        }
        let target = CanonicalChainRef::new(
            self.network,
            observed.canonical_head.canonical_ref().chain_epoch(),
            intent.target,
        );
        let plan = RollbackParticipantPlan::try_new(
            observed.canonical_head,
            target,
            intent.fence_window,
            topology.revision(),
            *topology.digest(),
            topology.realms().to_vec(),
        )?;
        store
            .persist_verified_rollback_participant_plan(&plan)
            .await?;
        let stored = store
            .read_verified_rollback_participant_plan(self.network, *plan.digest())
            .await?;
        if stored != plan {
            anyhow::bail!("ROLLBACK_PARTICIPANT_PLAN_READBACK_MISMATCH");
        }
        let receipt = self
            .start(RollbackAdminStartIntent::new(
                intent.expected_revision,
                intent.expected_canonical_ref,
                intent.target,
                intent.fence_window,
                RollbackExecutionMode::InPlace,
                RollbackPlanDigest::try_new(*plan.digest())?,
            ))
            .await?;
        let topology_after = store
            .read_current_rollback_topology(self.network)
            .await?
            .ok_or_else(|| anyhow::anyhow!("ROLLBACK_TOPOLOGY_UNINITIALIZED"))?;
        if topology_after != topology {
            anyhow::bail!("ROLLBACK_TOPOLOGY_CHANGED_AFTER_INBOX_OFFER");
        }
        Ok(receipt)
    }

    pub async fn status(&self) -> anyhow::Result<RollbackAdminInboxStatus<Hash>> {
        match self.read_status_fresh().await {
            Ok(status) => {
                self.cache_status(&status).await;
                Ok(status)
            }
            Err(error) => {
                self.cache_maintenance_state(CachedRollbackMaintenanceState::Unavailable(
                    format!("{error:#}"),
                ))
                .await;
                Err(error)
            }
        }
    }

    async fn read_status_fresh(&self) -> anyhow::Result<RollbackAdminInboxStatus<Hash>> {
        // The two rows cannot be read atomically. Bracket the inbox read with
        // the authoritative head and only return an observation for which the
        // head was stable. This closes the old-IDLE/new-empty false-IDLE window
        // while retaining single-row LWT as the write primitive.
        for _ in 0..3 {
            let before = self.read_head().await?;
            let slot = self.read_slot().await?;
            let after = self.read_head().await?;
            if before == after {
                return Ok(classify_status(after, slot));
            }
        }
        anyhow::bail!("ROLLBACK_ADMIN_STATUS_OBSERVATION_UNSTABLE")
    }

    /// Fail-closed admission check for Coordinator Edge operations which can
    /// create work or mutate state.
    pub async fn require_service_available(
        &self,
    ) -> anyhow::Result<RollbackMaintenancePermit<Hash>> {
        let mut cache = self.maintenance_cache.lock().await;
        if let Some(observation) = cache.as_ref() {
            if observation.observed_at.elapsed() < MAINTENANCE_GATE_CACHE_TTL {
                return observation.state.result();
            }
        }

        let state = match self.read_status_fresh().await {
            Ok(status) => maintenance_state_from_status(&status),
            Err(error) => CachedRollbackMaintenanceState::Unavailable(format!("{error:#}")),
        };
        *cache = Some(CachedRollbackMaintenanceObservation {
            observed_at: Instant::now(),
            state,
        });
        cache.as_ref().unwrap().state.result()
    }

    async fn cache_status(&self, status: &RollbackAdminInboxStatus<Hash>) {
        self.cache_maintenance_state(maintenance_state_from_status(status))
            .await;
    }

    async fn cache_maintenance_state(&self, state: CachedRollbackMaintenanceState<Hash>) {
        *self.maintenance_cache.lock().await = Some(CachedRollbackMaintenanceObservation {
            observed_at: Instant::now(),
            state,
        });
    }

    async fn start(
        &self,
        intent: RollbackAdminStartIntent<Hash>,
    ) -> anyhow::Result<RollbackAdminStartReceipt<Hash>> {
        let observed = self.status().await?;
        if self.access == RollbackAdminInboxAccess::Disabled {
            return Ok(receipt(RollbackAdminStartDisposition::Disabled, observed));
        }
        if !observed.canonical_head.rollback_control().is_idle() {
            return Ok(receipt(
                RollbackAdminStartDisposition::AlreadyActive,
                observed,
            ));
        }
        if observed.canonical_head.revision() != intent.expected_revision
            || observed.canonical_head.canonical_ref() != intent.expected_canonical_ref()
        {
            return Ok(receipt(
                RollbackAdminStartDisposition::HeadMismatch,
                observed,
            ));
        }

        let request = RollbackRequest::try_new(
            *observed.canonical_head.canonical_ref().checkpoint(),
            intent.target,
            intent.fence_window,
            intent.execution_mode,
            intent.plan_digest,
        )?;
        let command = RollbackAdmissionCommand::try_new(observed.canonical_head, request)?;

        match observed.admission_slot.state() {
            RollbackAdmissionSlotState::Pending(current) if *current == command => {
                return Ok(receipt(
                    RollbackAdminStartDisposition::Idempotent,
                    observed,
                ));
            }
            RollbackAdmissionSlotState::Pending(_) => {
                return Ok(receipt(RollbackAdminStartDisposition::Conflict, observed));
            }
            RollbackAdmissionSlotState::Empty => {}
        }

        let offer = SealedRollbackAdmissionSlotCas::offer(
            self.network,
            observed.admission_slot,
            command,
        )?;
        let (disposition, slot) = match self
            .admission_store
            .compare_and_set_rollback_admission_slot(&offer)
            .await?
        {
            RollbackAdmissionSlotWriteOutcome::Applied(slot) => {
                (RollbackAdminStartDisposition::Accepted, slot)
            }
            RollbackAdmissionSlotWriteOutcome::Idempotent(slot) => {
                (RollbackAdminStartDisposition::Idempotent, slot)
            }
            RollbackAdmissionSlotWriteOutcome::Conflict { current }
                if current.state().pending() == Some(&command) =>
            {
                (RollbackAdminStartDisposition::Idempotent, current)
            }
            RollbackAdmissionSlotWriteOutcome::Conflict { current } => {
                (RollbackAdminStartDisposition::Conflict, current)
            }
        };
        let receipt = receipt(
            disposition,
            classify_status(observed.canonical_head, slot),
        );
        self.cache_status(receipt.status()).await;
        Ok(receipt)
    }

    async fn read_head(&self) -> anyhow::Result<StoredCanonicalHead<Hash>> {
        match self
            .canonical_head_reader
            .read_canonical_head(self.network)
            .await?
        {
            CanonicalHeadReadState::Uninitialized => {
                anyhow::bail!("ROLLBACK_ADMIN_CANONICAL_HEAD_UNINITIALIZED")
            }
            CanonicalHeadReadState::Current(head) => Ok(head),
        }
    }

    async fn read_slot(&self) -> anyhow::Result<StoredRollbackAdmissionSlot<Hash>> {
        match self
            .admission_store
            .read_rollback_admission_slot(self.network)
            .await?
        {
            RollbackAdmissionSlotReadState::Uninitialized => {
                anyhow::bail!("ROLLBACK_ADMIN_INBOX_UNINITIALIZED")
            }
            RollbackAdmissionSlotReadState::Current(slot) => Ok(slot),
        }
    }
}

fn maintenance_state_from_status<Hash: Q256BitHash>(
    status: &RollbackAdminInboxStatus<Hash>,
) -> CachedRollbackMaintenanceState<Hash> {
    match status.phase() {
        RollbackAdminInboxPhase::Idle => {
            CachedRollbackMaintenanceState::Available(RollbackMaintenancePermit {
                canonical_head: *status.canonical_head(),
                inbox_revision: status.admission_slot().revision(),
            })
        }
        phase => CachedRollbackMaintenanceState::Blocked(phase),
    }
}

fn classify_status<Hash: Q256BitHash>(
    canonical_head: StoredCanonicalHead<Hash>,
    admission_slot: StoredRollbackAdmissionSlot<Hash>,
) -> RollbackAdminInboxStatus<Hash> {
    let phase = if !canonical_head.rollback_control().is_idle() {
        RollbackAdminInboxPhase::Active
    } else {
        match admission_slot.state() {
            RollbackAdmissionSlotState::Empty => RollbackAdminInboxPhase::Idle,
            RollbackAdmissionSlotState::Pending(command)
                if command.expected() == &canonical_head =>
            {
                RollbackAdminInboxPhase::Pending
            }
            RollbackAdmissionSlotState::Pending(_) => RollbackAdminInboxPhase::Stale,
        }
    };
    RollbackAdminInboxStatus {
        canonical_head,
        admission_slot,
        phase,
    }
}

const fn receipt<Hash>(
    disposition: RollbackAdminStartDisposition,
    status: RollbackAdminInboxStatus<Hash>,
) -> RollbackAdminStartReceipt<Hash> {
    RollbackAdminStartReceipt {
        disposition,
        status,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use async_trait::async_trait;
    use parth_core::PHash;
    use psy_data::protocol::canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef,
    };
    use tokio::sync::Mutex;

    use super::*;
    use crate::store::{
        canonical_head::{CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile},
        rollback_admission::{
            RollbackAdmissionSlotBootstrap, RollbackAdmissionSlotWriteOutcome,
        },
        rollback_topology::RollbackTopologySnapshot,
        timestamp::CommitWriteTimestampUs,
    };

    #[derive(Clone)]
    struct MemoryCanonicalHead {
        state: Arc<Mutex<CanonicalHeadReadState<PHash>>>,
        reads: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl CoordinatorCanonicalHeadReader<PHash> for MemoryCanonicalHead {
        async fn read_canonical_head(
            &self,
            _network: NetworkId,
        ) -> anyhow::Result<CanonicalHeadReadState<PHash>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(*self.state.lock().await)
        }
    }

    struct TransitioningHeadReader {
        reads: AtomicUsize,
        old: StoredCanonicalHead<PHash>,
        active: StoredCanonicalHead<PHash>,
    }

    #[async_trait]
    impl CoordinatorCanonicalHeadReader<PHash> for TransitioningHeadReader {
        async fn read_canonical_head(
            &self,
            _network: NetworkId,
        ) -> anyhow::Result<CanonicalHeadReadState<PHash>> {
            let read = self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(CanonicalHeadReadState::Current(if read == 0 {
                self.old
            } else {
                self.active
            }))
        }
    }

    #[derive(Clone)]
    struct MemoryAdmissionStore {
        state: Arc<Mutex<RollbackAdmissionSlotReadState<PHash>>>,
        reads: Arc<AtomicUsize>,
    }

    #[derive(Clone)]
    struct MemoryParticipantPlanStore {
        topology: RollbackTopologySnapshot,
        plan: Arc<Mutex<Option<Vec<u8>>>>,
        persists: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl CoordinatorRollbackParticipantPlanStore<PHash> for MemoryParticipantPlanStore {
        async fn read_current_rollback_topology(
            &self,
            requested: NetworkId,
        ) -> anyhow::Result<Option<RollbackTopologySnapshot>> {
            if requested != self.topology.network() {
                anyhow::bail!("wrong network");
            }
            Ok(Some(self.topology.clone()))
        }

        async fn persist_verified_rollback_participant_plan(
            &self,
            plan: &RollbackParticipantPlan<PHash>,
        ) -> anyhow::Result<()> {
            if !self.topology.validates_plan(plan) {
                anyhow::bail!("topology mismatch");
            }
            self.persists.fetch_add(1, Ordering::SeqCst);
            let mut stored = self.plan.lock().await;
            match stored.as_ref() {
                Some(bytes) if bytes == plan.canonical_bytes() => Ok(()),
                Some(_) => anyhow::bail!("plan conflict"),
                None => {
                    *stored = Some(plan.canonical_bytes().to_vec());
                    Ok(())
                }
            }
        }

        async fn read_verified_rollback_participant_plan(
            &self,
            requested: NetworkId,
            digest: [u8; 32],
        ) -> anyhow::Result<RollbackParticipantPlan<PHash>> {
            if requested != self.topology.network() {
                anyhow::bail!("wrong network");
            }
            let bytes = self
                .plan
                .lock()
                .await
                .clone()
                .ok_or_else(|| anyhow::anyhow!("missing plan"))?;
            let plan = RollbackParticipantPlan::decode_canonical(&bytes)?;
            if plan.digest() != &digest {
                anyhow::bail!("wrong digest");
            }
            Ok(plan)
        }
    }

    #[async_trait]
    impl super::super::rollback_admission::CoordinatorRollbackAdmissionReader<PHash>
        for MemoryAdmissionStore
    {
        async fn read_rollback_admission_slot(
            &self,
            _network: NetworkId,
        ) -> anyhow::Result<RollbackAdmissionSlotReadState<PHash>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(*self.state.lock().await)
        }
    }

    #[async_trait]
    impl CoordinatorRollbackAdmissionStore<PHash> for MemoryAdmissionStore {
        async fn bootstrap_rollback_admission_slot(
            &self,
            bootstrap: &RollbackAdmissionSlotBootstrap<PHash>,
        ) -> anyhow::Result<RollbackAdmissionSlotWriteOutcome<PHash>> {
            let mut state = self.state.lock().await;
            match *state {
                RollbackAdmissionSlotReadState::Uninitialized => {
                    let candidate = *bootstrap.candidate();
                    *state = RollbackAdmissionSlotReadState::Current(candidate);
                    Ok(RollbackAdmissionSlotWriteOutcome::Applied(candidate))
                }
                RollbackAdmissionSlotReadState::Current(current) => Ok(bootstrap
                    .classify_lwt_observation(false, current)),
            }
        }

        async fn compare_and_set_rollback_admission_slot(
            &self,
            sealed: &SealedRollbackAdmissionSlotCas<PHash>,
        ) -> anyhow::Result<RollbackAdmissionSlotWriteOutcome<PHash>> {
            let mut state = self.state.lock().await;
            let RollbackAdmissionSlotReadState::Current(current) = *state else {
                anyhow::bail!("uninitialized")
            };
            if &current == sealed.expected() {
                let candidate = *sealed.candidate();
                *state = RollbackAdmissionSlotReadState::Current(candidate);
                Ok(sealed.classify_lwt_observation(true, candidate))
            } else {
                Ok(sealed.classify_lwt_observation(false, current))
            }
        }
    }

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

    struct Fixture {
        service: Arc<CoordinatorRollbackAdminInbox<PHash>>,
        head_store: MemoryCanonicalHead,
        admission_store: MemoryAdmissionStore,
        participant_store: MemoryParticipantPlanStore,
        head: StoredCanonicalHead<PHash>,
    }

    fn fixture(access: RollbackAdminInboxAccess) -> Fixture {
        let head = *CanonicalHeadBootstrap::try_new(
            CanonicalHeadBootstrapProfile::PostGenesisFloor,
            CanonicalChainRef::new(network(), ChainEpoch::new(0), checkpoint(100, 10)),
        )
        .unwrap()
        .candidate();
        let slot = *RollbackAdmissionSlotBootstrap::<PHash>::new(network()).candidate();
        let head_store = MemoryCanonicalHead {
            state: Arc::new(Mutex::new(CanonicalHeadReadState::Current(head))),
            reads: Arc::new(AtomicUsize::new(0)),
        };
        let admission_store = MemoryAdmissionStore {
            state: Arc::new(Mutex::new(RollbackAdmissionSlotReadState::Current(slot))),
            reads: Arc::new(AtomicUsize::new(0)),
        };
        let participant_store = MemoryParticipantPlanStore {
            topology: RollbackTopologySnapshot::try_new(
                network(),
                0,
                vec![super::super::rollback_participant_plan::RollbackRealmParticipant::new(
                    0, 1,
                )],
            )
            .unwrap(),
            plan: Arc::new(Mutex::new(None)),
            persists: Arc::new(AtomicUsize::new(0)),
        };
        let service = Arc::new(
            CoordinatorRollbackAdminInbox::new(
                network(),
                access,
                Arc::new(head_store.clone()),
                Arc::new(admission_store.clone()),
            )
            .with_participant_plan_store(Arc::new(participant_store.clone())),
        );
        Fixture {
            service,
            head_store,
            admission_store,
            participant_store,
            head,
        }
    }

    fn intent(head: StoredCanonicalHead<PHash>, target: CheckpointRef<PHash>) -> RollbackAdminStartIntent<PHash> {
        RollbackAdminStartIntent::new(
            head.revision(),
            *head.canonical_ref(),
            target,
            TimestampFenceWindow::try_new(
                CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
                1_001,
                1_002,
            )
            .unwrap(),
            RollbackExecutionMode::InPlace,
            RollbackPlanDigest::try_new([0xA5; 32]).unwrap(),
        )
    }

    fn planned_intent(fixture: &Fixture) -> RollbackAdminPlannedStartIntent<PHash> {
        RollbackAdminPlannedStartIntent::new(
            fixture.head.revision(),
            *fixture.head.canonical_ref(),
            checkpoint(90, 20),
            TimestampFenceWindow::try_new(
                CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
                1_001,
                1_002,
            )
            .unwrap(),
            fixture.participant_store.topology.revision(),
            *fixture.participant_store.topology.digest(),
        )
    }

    #[tokio::test]
    async fn planned_start_persists_topology_selected_plan_before_inbox_offer() {
        let fixture = fixture(RollbackAdminInboxAccess::ManualPreflight);
        let receipt = fixture
            .service
            .start_planned(planned_intent(&fixture))
            .await
            .unwrap();
        assert_eq!(receipt.disposition(), RollbackAdminStartDisposition::Accepted);
        assert_eq!(receipt.status().phase(), RollbackAdminInboxPhase::Pending);
        let stored = fixture.participant_store.plan.lock().await.clone().unwrap();
        let plan = RollbackParticipantPlan::<PHash>::decode_canonical(&stored).unwrap();
        let pending = receipt
            .status()
            .admission_slot()
            .state()
            .pending()
            .unwrap();
        assert_eq!(pending.request().plan_digest().as_bytes(), plan.digest());
        assert_eq!(plan.realms(), fixture.participant_store.topology.realms());
        assert_eq!(fixture.participant_store.persists.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn planned_start_rejects_wrong_topology_before_plan_or_inbox_write() {
        let fixture = fixture(RollbackAdminInboxAccess::ManualPreflight);
        let mut intent = planned_intent(&fixture);
        intent.topology_digest[0] ^= 1;
        assert!(fixture
            .service
            .start_planned(intent)
            .await
            .unwrap_err()
            .to_string()
            .contains("ROLLBACK_TOPOLOGY_EXPECTATION_MISMATCH"));
        assert!(fixture.participant_store.plan.lock().await.is_none());
        let state = fixture.admission_store.state.lock().await;
        let RollbackAdmissionSlotReadState::Current(slot) = *state else {
            panic!("slot must remain initialized")
        };
        assert!(slot.state().is_empty());
    }

    #[tokio::test]
    async fn disabled_is_fail_closed_and_does_not_mutate_inbox() {
        let fixture = fixture(RollbackAdminInboxAccess::Disabled);
        let permit = fixture
            .service
            .require_service_available()
            .await
            .unwrap();
        assert_eq!(permit.canonical_head(), &fixture.head);
        assert_eq!(permit.inbox_revision().get(), 0);
        let receipt = fixture
            .service
            .start(intent(fixture.head, checkpoint(90, 20)))
            .await
            .unwrap();
        assert_eq!(receipt.disposition(), RollbackAdminStartDisposition::Disabled);
        assert_eq!(receipt.status().phase(), RollbackAdminInboxPhase::Idle);
        let state = fixture.admission_store.state.lock().await;
        let RollbackAdmissionSlotReadState::Current(slot) = *state else {
            panic!("slot must remain initialized")
        };
        assert!(slot.state().is_empty());
    }

    #[tokio::test]
    async fn idle_gate_observation_is_briefly_cached_on_the_hot_path() {
        let fixture = fixture(RollbackAdminInboxAccess::ManualPreflight);
        let first = fixture
            .service
            .require_service_available()
            .await
            .unwrap();
        let second = fixture
            .service
            .require_service_available()
            .await
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(fixture.head_store.reads.load(Ordering::SeqCst), 2);
        assert_eq!(fixture.admission_store.reads.load(Ordering::SeqCst), 1);

        *fixture.head_store.state.lock().await = CanonicalHeadReadState::Uninitialized;
        assert!(fixture.service.status().await.is_err());
        *fixture.head_store.state.lock().await = CanonicalHeadReadState::Current(fixture.head);
        assert!(
            fixture
                .service
                .require_service_available()
                .await
                .unwrap_err()
                .to_string()
                .contains("ROLLBACK_ADMIN_CANONICAL_HEAD_UNINITIALIZED"),
            "a failed forced refresh must invalidate a cached IDLE permit"
        );
    }

    #[tokio::test]
    async fn maintenance_gate_fails_closed_when_durable_authority_is_unavailable() {
        let head_fixture = fixture(RollbackAdminInboxAccess::ManualPreflight);
        *head_fixture.head_store.state.lock().await = CanonicalHeadReadState::Uninitialized;
        assert!(
            head_fixture
                .service
                .require_service_available()
                .await
                .unwrap_err()
                .to_string()
                .contains("ROLLBACK_ADMIN_CANONICAL_HEAD_UNINITIALIZED")
        );

        let inbox_fixture = fixture(RollbackAdminInboxAccess::ManualPreflight);
        *inbox_fixture.admission_store.state.lock().await =
            RollbackAdmissionSlotReadState::Uninitialized;
        assert!(
            inbox_fixture
                .service
                .require_service_available()
                .await
                .unwrap_err()
                .to_string()
                .contains("ROLLBACK_ADMIN_INBOX_UNINITIALIZED")
        );
    }

    #[tokio::test]
    async fn exact_request_is_accepted_then_idempotent() {
        let fixture = fixture(RollbackAdminInboxAccess::ManualPreflight);
        let intent = intent(fixture.head, checkpoint(90, 20));
        let first = fixture.service.start(intent).await.unwrap();
        assert_eq!(first.disposition(), RollbackAdminStartDisposition::Accepted);
        assert_eq!(first.status().phase(), RollbackAdminInboxPhase::Pending);
        let retry = fixture.service.start(intent).await.unwrap();
        assert_eq!(retry.disposition(), RollbackAdminStartDisposition::Idempotent);
        assert_eq!(
            retry.status().admission_slot().revision(),
            first.status().admission_slot().revision()
        );
    }

    #[tokio::test]
    async fn stale_expected_head_and_different_pending_command_fail_closed() {
        let fixture = fixture(RollbackAdminInboxAccess::ManualPreflight);
        let mut stale = intent(fixture.head, checkpoint(90, 20));
        stale.expected_revision = CanonicalHeadRevision::try_new(1).unwrap();
        assert_eq!(
            fixture.service.start(stale).await.unwrap().disposition(),
            RollbackAdminStartDisposition::HeadMismatch
        );

        fixture
            .service
            .start(intent(fixture.head, checkpoint(90, 20)))
            .await
            .unwrap();
        assert_eq!(
            fixture
                .service
                .start(intent(fixture.head, checkpoint(80, 30)))
                .await
                .unwrap()
                .disposition(),
            RollbackAdminStartDisposition::Conflict
        );
    }

    #[tokio::test]
    async fn status_distinguishes_pending_stale_and_active() {
        let fixture = fixture(RollbackAdminInboxAccess::ManualPreflight);
        fixture
            .service
            .start(intent(fixture.head, checkpoint(90, 20)))
            .await
            .unwrap();
        assert_eq!(
            fixture.service.status().await.unwrap().phase(),
            RollbackAdminInboxPhase::Pending
        );
        let pending = fixture
            .service
            .require_service_available()
            .await
            .unwrap_err();
        assert_eq!(
            pending
                .downcast_ref::<RollbackMaintenanceGateError>()
                .unwrap()
                .phase(),
            RollbackAdminInboxPhase::Pending
        );

        let advanced = *super::super::canonical_head::CanonicalHeadTransition::normal_checkpoint_advance(
            fixture.head,
            CanonicalChainRef::new(network(), ChainEpoch::new(0), checkpoint(101, 40)),
        )
        .unwrap()
        .seal()
        .candidate();
        *fixture.head_store.state.lock().await = CanonicalHeadReadState::Current(advanced);
        assert_eq!(
            fixture.service.status().await.unwrap().phase(),
            RollbackAdminInboxPhase::Stale
        );
        let stale = fixture
            .service
            .require_service_available()
            .await
            .unwrap_err();
        assert_eq!(
            stale
                .downcast_ref::<RollbackMaintenanceGateError>()
                .unwrap()
                .phase(),
            RollbackAdminInboxPhase::Stale
        );

        let slot = match *fixture.admission_store.state.lock().await {
            RollbackAdmissionSlotReadState::Current(slot) => slot,
            RollbackAdmissionSlotReadState::Uninitialized => unreachable!(),
        };
        let command = *slot.state().pending().unwrap();
        *fixture.head_store.state.lock().await =
            CanonicalHeadReadState::Current(*command.sealed().candidate());
        assert_eq!(
            fixture.service.status().await.unwrap().phase(),
            RollbackAdminInboxPhase::Active
        );
        let active = fixture
            .service
            .require_service_available()
            .await
            .unwrap_err();
        assert_eq!(
            active
                .downcast_ref::<RollbackMaintenanceGateError>()
                .unwrap()
                .phase(),
            RollbackAdminInboxPhase::Active
        );
    }

    #[tokio::test]
    async fn bracketed_status_read_never_reports_false_idle_during_admission() {
        let fixture = fixture(RollbackAdminInboxAccess::ManualPreflight);
        let request = RollbackRequest::try_new(
            *fixture.head.canonical_ref().checkpoint(),
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
        .unwrap();
        let active = *super::super::canonical_head::CanonicalHeadTransition::start_rollback(
            fixture.head,
            request,
        )
        .unwrap()
        .seal()
        .candidate();
        let service = CoordinatorRollbackAdminInbox::new(
            network(),
            RollbackAdminInboxAccess::ManualPreflight,
            Arc::new(TransitioningHeadReader {
                reads: AtomicUsize::new(0),
                old: fixture.head,
                active,
            }),
            Arc::new(fixture.admission_store),
        );
        assert_eq!(
            service.status().await.unwrap().phase(),
            RollbackAdminInboxPhase::Active
        );
    }

    #[tokio::test]
    async fn competing_edge_requests_have_one_winner() {
        let fixture = fixture(RollbackAdminInboxAccess::ManualPreflight);
        let a = intent(fixture.head, checkpoint(90, 20));
        let b = intent(fixture.head, checkpoint(80, 30));
        let mut tasks = Vec::new();
        for index in 0..64 {
            let service = fixture.service.clone();
            tasks.push(tokio::spawn(async move {
                service.start(if index % 2 == 0 { a } else { b }).await.unwrap()
            }));
        }
        let mut accepted = 0;
        let mut idempotent = 0;
        let mut conflict = 0;
        for task in tasks {
            match task.await.unwrap().disposition() {
                RollbackAdminStartDisposition::Accepted => accepted += 1,
                RollbackAdminStartDisposition::Idempotent => idempotent += 1,
                RollbackAdminStartDisposition::Conflict => conflict += 1,
                other => panic!("unexpected outcome: {other:?}"),
            }
        }
        assert_eq!(accepted, 1);
        assert_eq!(accepted + idempotent + conflict, 64);
        assert!(idempotent > 0);
        assert!(conflict > 0);
    }

    #[test]
    fn edge_service_has_no_canonical_head_writer_capability() {
        fn assert_reader_only(
            _: &Arc<dyn CoordinatorCanonicalHeadReader<PHash>>,
        ) {
        }
        let fixture = fixture(RollbackAdminInboxAccess::ManualPreflight);
        assert_reader_only(&fixture.service.canonical_head_reader);
    }
}
