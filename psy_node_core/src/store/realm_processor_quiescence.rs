//! Process-local ownership boundary for one Realm Processor iteration.
//!
//! The real Realm loop is already a single actor, but h22e3 used a synthetic
//! `{guarded, in_flight, publishing}` observation. This module makes the
//! iteration owner and its quiescence proof unforgeable outside this gate.
//! It deliberately proves only that `sync + process/commit/publish` is idle;
//! the independent gatherer must be paused and acknowledged before a later
//! integration may convert this lease into cutover authority.

use std::{
    error::Error,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};

use psy_data::protocol::canonical_chain::NetworkId;
use sha2::{Digest, Sha256};

const DRAIN_REQUEST_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-iteration-drain/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RealmProcessorGuardRevision(u64);

impl RealmProcessorGuardRevision {
    pub const fn get(self) -> u64 {
        self.0
    }

    fn checked_next(self) -> Result<Self, RealmProcessorQuiescenceError> {
        let next = self
            .0
            .checked_add(1)
            .ok_or(RealmProcessorQuiescenceError::RevisionOverflow)?;
        if next > i64::MAX as u64 {
            return Err(RealmProcessorQuiescenceError::RevisionOverflow);
        }
        Ok(Self(next))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmProcessorDrainRequestDigest([u8; 32]);

impl RealmProcessorDrainRequestDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact durable-route expectation which asks the process-local owner to stop
/// admitting another iteration. It does not itself authorize a route CAS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmProcessorDrainRequest {
    network: NetworkId,
    realm_id: u32,
    realm_sub_id: u16,
    route_generation: u64,
    route_revision: u64,
    binding_digest: [u8; 32],
    decision_nonce: [u8; 32],
    digest: RealmProcessorDrainRequestDigest,
}

impl RealmProcessorDrainRequest {
    pub fn try_new(
        network: NetworkId,
        realm_id: u32,
        realm_sub_id: u16,
        route_generation: u64,
        route_revision: u64,
        binding_digest: [u8; 32],
        decision_nonce: [u8; 32],
    ) -> Result<Self, RealmProcessorQuiescenceError> {
        if route_generation > i64::MAX as u64 || route_revision > i64::MAX as u64 {
            return Err(RealmProcessorQuiescenceError::RouteRevisionOutOfRange);
        }
        if binding_digest.iter().all(|byte| *byte == 0) {
            return Err(RealmProcessorQuiescenceError::ZeroBindingDigest);
        }
        if decision_nonce.iter().all(|byte| *byte == 0) {
            return Err(RealmProcessorQuiescenceError::ZeroDecisionNonce);
        }
        let mut hasher = Sha256::new();
        hasher.update(DRAIN_REQUEST_DIGEST_DOMAIN);
        hasher.update(network.chain_id().to_be_bytes());
        hasher.update(realm_id.to_be_bytes());
        hasher.update(realm_sub_id.to_be_bytes());
        hasher.update(route_generation.to_be_bytes());
        hasher.update(route_revision.to_be_bytes());
        hasher.update(binding_digest);
        hasher.update(decision_nonce);
        let digest = RealmProcessorDrainRequestDigest(hasher.finalize().into());
        Ok(Self {
            network,
            realm_id,
            realm_sub_id,
            route_generation,
            route_revision,
            binding_digest,
            decision_nonce,
            digest,
        })
    }

    pub const fn network(self) -> NetworkId {
        self.network
    }

    pub const fn realm_id(self) -> u32 {
        self.realm_id
    }

    pub const fn realm_sub_id(self) -> u16 {
        self.realm_sub_id
    }

    pub const fn route_generation(self) -> u64 {
        self.route_generation
    }

    pub const fn route_revision(self) -> u64 {
        self.route_revision
    }

    pub const fn binding_digest(self) -> [u8; 32] {
        self.binding_digest
    }

    pub const fn decision_nonce(self) -> [u8; 32] {
        self.decision_nonce
    }

    pub const fn digest(self) -> RealmProcessorDrainRequestDigest {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmProcessorQuiescencePhase {
    Disabled,
    Running,
    DrainRequested,
    IterationDrained,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmProcessorQuiescenceSnapshot {
    phase: RealmProcessorQuiescencePhase,
    revision: RealmProcessorGuardRevision,
    active_iteration: bool,
    request_digest: Option<RealmProcessorDrainRequestDigest>,
}

impl RealmProcessorQuiescenceSnapshot {
    pub const fn phase(self) -> RealmProcessorQuiescencePhase {
        self.phase
    }

    pub const fn revision(self) -> RealmProcessorGuardRevision {
        self.revision
    }

    pub const fn active_iteration(self) -> bool {
        self.active_iteration
    }

    pub const fn request_digest(self) -> Option<RealmProcessorDrainRequestDigest> {
        self.request_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmProcessorDrainRequestOutcome {
    Applied(RealmProcessorQuiescenceSnapshot),
    Idempotent(RealmProcessorQuiescenceSnapshot),
}

#[derive(Debug)]
enum ControlledPhase {
    Running,
    DrainRequested(RealmProcessorDrainRequest),
    IterationDrained(RealmProcessorDrainRequest),
}

#[derive(Debug)]
enum GateMode {
    Disabled,
    Controlled {
        revision: RealmProcessorGuardRevision,
        phase: ControlledPhase,
        active_iteration: Option<u64>,
        next_iteration: u64,
    },
}

#[derive(Debug)]
struct GateState {
    mode: GateMode,
}

/// Cloneable command-side handle. Only an iteration permit minted by this
/// exact instance can affect the active count, and only this gate can mint an
/// iteration-drained lease.
#[derive(Clone, Debug)]
pub struct RealmProcessorIterationGate {
    state: Arc<Mutex<GateState>>,
}

impl Default for RealmProcessorIterationGate {
    fn default() -> Self {
        Self::disabled()
    }
}

impl RealmProcessorIterationGate {
    pub fn disabled() -> Self {
        Self::with_mode(GateMode::Disabled)
    }

    /// Explicit opt-in used by a future Processor composition root. Merely
    /// constructing this gate does not prepare Scylla or enable target I/O.
    pub fn controlled() -> Self {
        Self::with_mode(GateMode::Controlled {
            revision: RealmProcessorGuardRevision(0),
            phase: ControlledPhase::Running,
            active_iteration: None,
            next_iteration: 1,
        })
    }

    fn with_mode(mode: GateMode) -> Self {
        Self {
            state: Arc::new(Mutex::new(GateState { mode })),
        }
    }

    /// Mint the sole owner for one complete `sync + process/commit/publish`
    /// iteration. New work fails closed after a drain request.
    pub fn try_begin_iteration(
        &self,
    ) -> Result<RealmProcessorIterationPermit, RealmProcessorQuiescenceError> {
        let mut state = self.lock();
        match &mut state.mode {
            GateMode::Disabled => Ok(RealmProcessorIterationPermit {
                state: None,
                iteration_id: 0,
            }),
            GateMode::Controlled {
                phase: ControlledPhase::Running,
                active_iteration,
                next_iteration,
                ..
            } => {
                if active_iteration.is_some() {
                    return Err(RealmProcessorQuiescenceError::IterationAlreadyActive);
                }
                let iteration_id = *next_iteration;
                *next_iteration = next_iteration
                    .checked_add(1)
                    .ok_or(RealmProcessorQuiescenceError::IterationIdOverflow)?;
                *active_iteration = Some(iteration_id);
                Ok(RealmProcessorIterationPermit {
                    state: Some(self.state.clone()),
                    iteration_id,
                })
            }
            GateMode::Controlled { .. } => {
                Err(RealmProcessorQuiescenceError::DrainInProgress)
            }
        }
    }

    pub fn request_drain(
        &self,
        request: RealmProcessorDrainRequest,
    ) -> Result<RealmProcessorDrainRequestOutcome, RealmProcessorQuiescenceError> {
        let mut state = self.lock();
        let GateMode::Controlled {
            revision, phase, active_iteration, ..
        } = &mut state.mode
        else {
            return Err(RealmProcessorQuiescenceError::Disabled);
        };
        match phase {
            ControlledPhase::Running => {
                *revision = revision.checked_next()?;
                *phase = ControlledPhase::DrainRequested(request);
                Ok(RealmProcessorDrainRequestOutcome::Applied(snapshot_controlled(
                    *revision,
                    phase,
                    *active_iteration,
                )))
            }
            ControlledPhase::DrainRequested(current)
            | ControlledPhase::IterationDrained(current)
                if *current == request =>
            {
                Ok(RealmProcessorDrainRequestOutcome::Idempotent(
                    snapshot_controlled(*revision, phase, *active_iteration),
                ))
            }
            ControlledPhase::DrainRequested(_) | ControlledPhase::IterationDrained(_) => {
                Err(RealmProcessorQuiescenceError::ConflictingDrainRequest)
            }
        }
    }

    /// Convert an exact, idle iteration boundary into an opaque lease. This
    /// is not yet a whole-Realm drain proof because the gatherer is independent.
    pub fn try_mint_iteration_drained(
        &self,
        request: RealmProcessorDrainRequest,
    ) -> Result<RealmProcessorIterationDrainedLease, RealmProcessorQuiescenceError> {
        let mut state = self.lock();
        let GateMode::Controlled {
            revision, phase, active_iteration, ..
        } = &mut state.mode
        else {
            return Err(RealmProcessorQuiescenceError::Disabled);
        };
        if active_iteration.is_some() {
            return Err(RealmProcessorQuiescenceError::IterationStillActive);
        }
        match phase {
            ControlledPhase::DrainRequested(current) if *current == request => {
                *revision = revision.checked_next()?;
                *phase = ControlledPhase::IterationDrained(request);
            }
            ControlledPhase::IterationDrained(current) if *current == request => {}
            ControlledPhase::Running => {
                return Err(RealmProcessorQuiescenceError::DrainNotRequested)
            }
            ControlledPhase::DrainRequested(_) | ControlledPhase::IterationDrained(_) => {
                return Err(RealmProcessorQuiescenceError::DrainRequestMismatch)
            }
        }
        Ok(RealmProcessorIterationDrainedLease {
            state: self.state.clone(),
            revision: *revision,
            request,
        })
    }

    pub fn require_current_iteration_drained(
        &self,
        lease: &RealmProcessorIterationDrainedLease,
    ) -> Result<(), RealmProcessorQuiescenceError> {
        if !Arc::ptr_eq(&self.state, &lease.state) {
            return Err(RealmProcessorQuiescenceError::LeaseFromDifferentGate);
        }
        let state = self.lock();
        let GateMode::Controlled {
            revision,
            phase: ControlledPhase::IterationDrained(current),
            active_iteration: None,
            ..
        } = &state.mode
        else {
            return Err(RealmProcessorQuiescenceError::StaleDrainedLease);
        };
        if *revision != lease.revision || *current != lease.request {
            return Err(RealmProcessorQuiescenceError::StaleDrainedLease);
        }
        Ok(())
    }

    pub fn resume(
        &self,
        lease: RealmProcessorIterationDrainedLease,
    ) -> Result<RealmProcessorQuiescenceSnapshot, RealmProcessorQuiescenceError> {
        if !Arc::ptr_eq(&self.state, &lease.state) {
            return Err(RealmProcessorQuiescenceError::LeaseFromDifferentGate);
        }
        let mut state = self.lock();
        let GateMode::Controlled {
            revision,
            phase,
            active_iteration,
            ..
        } = &mut state.mode
        else {
            return Err(RealmProcessorQuiescenceError::StaleDrainedLease);
        };
        let ControlledPhase::IterationDrained(current) = phase else {
            return Err(RealmProcessorQuiescenceError::StaleDrainedLease);
        };
        if active_iteration.is_some()
            || *revision != lease.revision
            || *current != lease.request
        {
            return Err(RealmProcessorQuiescenceError::StaleDrainedLease);
        }
        *revision = revision.checked_next()?;
        *phase = ControlledPhase::Running;
        Ok(snapshot_controlled(*revision, phase, None))
    }

    pub fn snapshot(&self) -> RealmProcessorQuiescenceSnapshot {
        let state = self.lock();
        match &state.mode {
            GateMode::Disabled => RealmProcessorQuiescenceSnapshot {
                phase: RealmProcessorQuiescencePhase::Disabled,
                revision: RealmProcessorGuardRevision(0),
                active_iteration: false,
                request_digest: None,
            },
            GateMode::Controlled {
                revision, phase, active_iteration, ..
            } => snapshot_controlled(*revision, phase, *active_iteration),
        }
    }

    fn lock(&self) -> MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// RAII owner held by the real Realm loop for one whole iteration. It cannot
/// be cloned or constructed by callers.
#[derive(Debug)]
pub struct RealmProcessorIterationPermit {
    state: Option<Arc<Mutex<GateState>>>,
    iteration_id: u64,
}

impl RealmProcessorIterationPermit {
    /// Only the sibling branch-exact owner may distinguish an explicitly
    /// controlled permit from the legacy disabled-mode compatibility permit.
    /// The permit remains opaque to callers outside the store crate.
    pub(super) const fn is_controlled(&self) -> bool {
        self.state.is_some()
    }
}

impl Drop for RealmProcessorIterationPermit {
    fn drop(&mut self) {
        let Some(state) = &self.state else {
            return;
        };
        let mut state = state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let GateMode::Controlled {
            active_iteration, ..
        } = &mut state.mode
        {
            if *active_iteration == Some(self.iteration_id) {
                *active_iteration = None;
            }
        }
    }
}

/// Opaque proof that the real loop has stopped admitting iterations and its
/// previous iteration owner has been released. This is intentionally not
/// `Clone`; a later bridge must additionally prove gatherer quiescence.
#[derive(Debug)]
pub struct RealmProcessorIterationDrainedLease {
    state: Arc<Mutex<GateState>>,
    revision: RealmProcessorGuardRevision,
    request: RealmProcessorDrainRequest,
}

impl RealmProcessorIterationDrainedLease {
    pub const fn revision(&self) -> RealmProcessorGuardRevision {
        self.revision
    }

    pub const fn request(&self) -> RealmProcessorDrainRequest {
        self.request
    }
}

fn snapshot_controlled(
    revision: RealmProcessorGuardRevision,
    phase: &ControlledPhase,
    active_iteration: Option<u64>,
) -> RealmProcessorQuiescenceSnapshot {
    let (phase, request_digest) = match phase {
        ControlledPhase::Running => (RealmProcessorQuiescencePhase::Running, None),
        ControlledPhase::DrainRequested(request) => (
            RealmProcessorQuiescencePhase::DrainRequested,
            Some(request.digest()),
        ),
        ControlledPhase::IterationDrained(request) => (
            RealmProcessorQuiescencePhase::IterationDrained,
            Some(request.digest()),
        ),
    };
    RealmProcessorQuiescenceSnapshot {
        phase,
        revision,
        active_iteration: active_iteration.is_some(),
        request_digest,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmProcessorQuiescenceError {
    Disabled,
    RouteRevisionOutOfRange,
    ZeroBindingDigest,
    ZeroDecisionNonce,
    RevisionOverflow,
    IterationIdOverflow,
    IterationAlreadyActive,
    DrainInProgress,
    ConflictingDrainRequest,
    IterationStillActive,
    DrainNotRequested,
    DrainRequestMismatch,
    LeaseFromDifferentGate,
    StaleDrainedLease,
}

impl fmt::Display for RealmProcessorQuiescenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmProcessorQuiescenceError {}

#[cfg(test)]
mod tests {
    use psy_core::constants::chain_id::PsyChainNetworkType;

    use super::*;

    fn request(nonce: u8) -> RealmProcessorDrainRequest {
        RealmProcessorDrainRequest::try_new(
            NetworkId::from_network_type(PsyChainNetworkType::LocalDevnet),
            7,
            3,
            11,
            19,
            [21; 32],
            [nonce; 32],
        )
        .unwrap()
    }

    #[test]
    fn disabled_is_default_and_preserves_iteration_admission() {
        let gate = RealmProcessorIterationGate::default();
        assert_eq!(gate.snapshot().phase(), RealmProcessorQuiescencePhase::Disabled);
        let first = gate.try_begin_iteration().unwrap();
        let second = gate.try_begin_iteration().unwrap();
        drop((first, second));
        assert_eq!(gate.request_drain(request(1)), Err(RealmProcessorQuiescenceError::Disabled));
    }

    #[test]
    fn controlled_gate_has_exactly_one_iteration_owner() {
        let gate = RealmProcessorIterationGate::controlled();
        let owner = gate.try_begin_iteration().unwrap();
        assert!(gate.snapshot().active_iteration());
        assert!(matches!(
            gate.try_begin_iteration(),
            Err(RealmProcessorQuiescenceError::IterationAlreadyActive)
        ));
        drop(owner);
        assert!(!gate.snapshot().active_iteration());
        drop(gate.try_begin_iteration().unwrap());
    }

    #[test]
    fn drain_during_iteration_waits_for_raii_release_and_blocks_next_work() {
        let gate = RealmProcessorIterationGate::controlled();
        let owner = gate.try_begin_iteration().unwrap();
        let request = request(1);
        let RealmProcessorDrainRequestOutcome::Applied(snapshot) =
            gate.request_drain(request).unwrap()
        else {
            panic!("first request must apply")
        };
        assert_eq!(snapshot.phase(), RealmProcessorQuiescencePhase::DrainRequested);
        assert!(snapshot.active_iteration());
        assert!(matches!(
            gate.try_begin_iteration(),
            Err(RealmProcessorQuiescenceError::DrainInProgress)
        ));
        assert!(matches!(
            gate.try_mint_iteration_drained(request),
            Err(RealmProcessorQuiescenceError::IterationStillActive)
        ));
        drop(owner);
        let lease = gate.try_mint_iteration_drained(request).unwrap();
        gate.require_current_iteration_drained(&lease).unwrap();
        assert_eq!(lease.revision().get(), 2);
    }

    #[test]
    fn exact_request_is_idempotent_but_conflicting_request_fails_closed() {
        let gate = RealmProcessorIterationGate::controlled();
        let first = request(1);
        assert!(matches!(
            gate.request_drain(first),
            Ok(RealmProcessorDrainRequestOutcome::Applied(_))
        ));
        assert!(matches!(
            gate.request_drain(first),
            Ok(RealmProcessorDrainRequestOutcome::Idempotent(_))
        ));
        assert_eq!(
            gate.request_drain(request(2)),
            Err(RealmProcessorQuiescenceError::ConflictingDrainRequest)
        );
    }

    #[test]
    fn resume_and_second_drain_reject_old_lease_without_aba() {
        let gate = RealmProcessorIterationGate::controlled();
        let first = request(1);
        gate.request_drain(first).unwrap();
        let stale_equivalent = gate.try_mint_iteration_drained(first).unwrap();
        let resume = gate.try_mint_iteration_drained(first).unwrap();
        assert_eq!(gate.resume(resume).unwrap().revision().get(), 3);
        assert_eq!(
            gate.require_current_iteration_drained(&stale_equivalent),
            Err(RealmProcessorQuiescenceError::StaleDrainedLease)
        );
        let second = request(2);
        gate.request_drain(second).unwrap();
        let current = gate.try_mint_iteration_drained(second).unwrap();
        assert_eq!(current.revision().get(), 5);
        assert_eq!(
            gate.require_current_iteration_drained(&stale_equivalent),
            Err(RealmProcessorQuiescenceError::StaleDrainedLease)
        );
    }

    #[test]
    fn lease_cannot_cross_gate_instances() {
        let first_gate = RealmProcessorIterationGate::controlled();
        let second_gate = RealmProcessorIterationGate::controlled();
        let request = request(1);
        first_gate.request_drain(request).unwrap();
        second_gate.request_drain(request).unwrap();
        let lease = first_gate.try_mint_iteration_drained(request).unwrap();
        assert_eq!(
            second_gate.require_current_iteration_drained(&lease),
            Err(RealmProcessorQuiescenceError::LeaseFromDifferentGate)
        );
    }

    #[test]
    fn malformed_request_is_rejected_before_state_change() {
        let network = NetworkId::from_network_type(PsyChainNetworkType::LocalDevnet);
        assert_eq!(
            RealmProcessorDrainRequest::try_new(network, 1, 0, 0, 0, [0; 32], [1; 32]),
            Err(RealmProcessorQuiescenceError::ZeroBindingDigest)
        );
        assert_eq!(
            RealmProcessorDrainRequest::try_new(network, 1, 0, 0, 0, [1; 32], [0; 32]),
            Err(RealmProcessorQuiescenceError::ZeroDecisionNonce)
        );
        assert_eq!(
            RealmProcessorDrainRequest::try_new(
                network,
                1,
                0,
                i64::MAX as u64 + 1,
                0,
                [1; 32],
                [2; 32],
            ),
            Err(RealmProcessorQuiescenceError::RouteRevisionOutOfRange)
        );
    }

    #[tokio::test]
    async fn cancellation_drops_the_iteration_owner() {
        let gate = RealmProcessorIterationGate::controlled();
        let task_gate = gate.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _owner = task_gate.try_begin_iteration().unwrap();
            started_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();
        let request = request(7);
        gate.request_drain(request).unwrap();
        assert!(matches!(
            gate.try_mint_iteration_drained(request),
            Err(RealmProcessorQuiescenceError::IterationStillActive)
        ));
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        gate.try_mint_iteration_drained(request).unwrap();
    }

    #[tokio::test]
    async fn concurrent_iteration_contenders_have_one_owner() {
        let gate = RealmProcessorIterationGate::controlled();
        let start = Arc::new(tokio::sync::Barrier::new(33));
        let release = Arc::new(tokio::sync::Barrier::new(33));
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let gate = gate.clone();
            let start = start.clone();
            let release = release.clone();
            tasks.push(tokio::spawn(async move {
                start.wait().await;
                let owner = gate.try_begin_iteration().ok();
                release.wait().await;
                owner.is_some()
            }));
        }
        start.wait().await;
        release.wait().await;
        let mut owners = 0;
        for task in tasks {
            owners += usize::from(task.await.unwrap());
        }
        assert_eq!(owners, 1);
    }
}
