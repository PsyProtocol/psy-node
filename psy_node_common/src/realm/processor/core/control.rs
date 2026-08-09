//! Process-local control plane owned by the real Realm Processor runner.
//!
//! The sender is bounded and observation-only. The receiver, iteration gate,
//! gatherer receipt, and whole-drained lease never leave the runner actor.

use std::fmt;

use psy_node_core::store::realm_processor_quiescence::{
    RealmProcessorDrainRequest, RealmProcessorDrainRequestDigest,
    RealmProcessorIterationDrainedLease, RealmProcessorIterationGate,
    RealmProcessorQuiescenceError,
};
use tokio::sync::{mpsc, oneshot, watch};

use crate::queue::gatherer::GathererPauseReceipt;

const CONTROL_MAILBOX_CAPACITY: usize = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmProcessorControlRevision(u64);

impl RealmProcessorControlRevision {
    pub const fn get(self) -> u64 {
        self.0
    }

    fn checked_next(self) -> Result<Self, RealmProcessorControlError> {
        let next = self
            .0
            .checked_add(1)
            .ok_or(RealmProcessorControlError::RevisionOverflow)?;
        if next > i64::MAX as u64 {
            return Err(RealmProcessorControlError::RevisionOverflow);
        }
        Ok(Self(next))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmProcessorControlPhase {
    Running,
    DrainRequested,
    IterationDrained,
    GathererPausePending,
    WholeDrained,
    FailedClosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmProcessorControlSnapshot {
    revision: RealmProcessorControlRevision,
    phase: RealmProcessorControlPhase,
    request_digest: Option<RealmProcessorDrainRequestDigest>,
}

impl RealmProcessorControlSnapshot {
    pub const fn revision(self) -> RealmProcessorControlRevision {
        self.revision
    }

    pub const fn phase(self) -> RealmProcessorControlPhase {
        self.phase
    }

    pub const fn request_digest(self) -> Option<RealmProcessorDrainRequestDigest> {
        self.request_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmProcessorDrainAcceptance {
    Applied(RealmProcessorControlSnapshot),
    Idempotent(RealmProcessorControlSnapshot),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmProcessorControlError {
    AlreadyEnabled,
    MailboxBusy,
    MailboxClosed,
    ResponseClosed,
    ConflictingRequest,
    RevisionOverflow,
    UnexpectedPhase,
    AuthorityIdentityMismatch,
    RequestMismatch,
    PendingContextMismatch,
    Quiescence(RealmProcessorQuiescenceError),
}

impl fmt::Display for RealmProcessorControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for RealmProcessorControlError {}

#[derive(Clone)]
pub struct RealmProcessorControlHandle {
    command_tx: mpsc::Sender<RealmProcessorControlCommand>,
    status_rx: watch::Receiver<RealmProcessorControlSnapshot>,
}

impl RealmProcessorControlHandle {
    pub fn snapshot(&self) -> RealmProcessorControlSnapshot {
        *self.status_rx.borrow()
    }

    pub async fn request_drain(
        &self,
        request: RealmProcessorDrainRequest,
    ) -> Result<RealmProcessorDrainAcceptance, RealmProcessorControlError> {
        let snapshot = self.snapshot();
        if snapshot.phase != RealmProcessorControlPhase::Running {
            return if snapshot.request_digest == Some(request.digest()) {
                Ok(RealmProcessorDrainAcceptance::Idempotent(snapshot))
            } else {
                Err(RealmProcessorControlError::ConflictingRequest)
            };
        }

        let (response_tx, response_rx) = oneshot::channel();
        self.command_tx
            .try_send(RealmProcessorControlCommand::RequestDrain {
                request,
                responder: response_tx,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => RealmProcessorControlError::MailboxBusy,
                mpsc::error::TrySendError::Closed(_) => {
                    RealmProcessorControlError::MailboxClosed
                }
            })?;
        response_rx
            .await
            .map_err(|_| RealmProcessorControlError::ResponseClosed)?
    }

    pub async fn changed(
        &mut self,
    ) -> Result<RealmProcessorControlSnapshot, RealmProcessorControlError> {
        self.status_rx
            .changed()
            .await
            .map_err(|_| RealmProcessorControlError::MailboxClosed)?;
        Ok(self.snapshot())
    }
}

enum RealmProcessorControlCommand {
    RequestDrain {
        request: RealmProcessorDrainRequest,
        responder: oneshot::Sender<
            Result<RealmProcessorDrainAcceptance, RealmProcessorControlError>,
        >,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmProcessorPendingContext {
    processing_unique_pending_id: u64,
    processing_proc_unique_id: u128,
    gathering_unique_pending_id: u64,
    gathering_proc_unique_id: u128,
}

impl RealmProcessorPendingContext {
    pub(crate) const fn new(
        processing_unique_pending_id: u64,
        processing_proc_unique_id: u128,
        gathering_unique_pending_id: u64,
        gathering_proc_unique_id: u128,
    ) -> Self {
        Self {
            processing_unique_pending_id,
            processing_proc_unique_id,
            gathering_unique_pending_id,
            gathering_proc_unique_id,
        }
    }

    pub const fn processing_unique_pending_id(self) -> u64 {
        self.processing_unique_pending_id
    }

    pub const fn processing_proc_unique_id(self) -> u128 {
        self.processing_proc_unique_id
    }

    pub const fn gathering_unique_pending_id(self) -> u64 {
        self.gathering_unique_pending_id
    }

    pub const fn gathering_proc_unique_id(self) -> u128 {
        self.gathering_proc_unique_id
    }
}

/// Opaque whole-Processor proof retained by the real runner. It is not Clone,
/// serializable, or an external status response.
#[derive(Debug)]
pub(crate) struct RealmProcessorWholeDrainedLease {
    iteration: RealmProcessorIterationDrainedLease,
    gatherer: GathererPauseReceipt,
    request: RealmProcessorDrainRequest,
    pending_context: RealmProcessorPendingContext,
    controller_revision: RealmProcessorControlRevision,
}

pub(super) struct RealmProcessorControlOwner {
    command_rx: mpsc::Receiver<RealmProcessorControlCommand>,
    status_tx: watch::Sender<RealmProcessorControlSnapshot>,
    current_request: Option<RealmProcessorDrainRequest>,
    whole_lease: Option<RealmProcessorWholeDrainedLease>,
}

pub(super) fn new_realm_processor_control_plane(
) -> (RealmProcessorControlOwner, RealmProcessorControlHandle) {
    let initial = RealmProcessorControlSnapshot {
        revision: RealmProcessorControlRevision(0),
        phase: RealmProcessorControlPhase::Running,
        request_digest: None,
    };
    let (command_tx, command_rx) = mpsc::channel(CONTROL_MAILBOX_CAPACITY);
    let (status_tx, status_rx) = watch::channel(initial);
    (
        RealmProcessorControlOwner {
            command_rx,
            status_tx,
            current_request: None,
            whole_lease: None,
        },
        RealmProcessorControlHandle {
            command_tx,
            status_rx,
        },
    )
}

impl RealmProcessorControlOwner {
    /// Linearize at most one queued request. A closed response before dequeue
    /// has no side effect; after `request_drain` applies, response loss cannot
    /// undo the drain.
    pub(super) fn try_accept_next(
        &mut self,
        gate: &RealmProcessorIterationGate,
        expected_chain_id: u32,
        expected_realm_id: u64,
        expected_realm_sub_id: u64,
    ) -> Result<Option<RealmProcessorDrainRequest>, RealmProcessorControlError> {
        loop {
            let command = match self.command_rx.try_recv() {
                Ok(command) => command,
                Err(mpsc::error::TryRecvError::Empty)
                | Err(mpsc::error::TryRecvError::Disconnected) => return Ok(None),
            };
            match command {
                RealmProcessorControlCommand::RequestDrain { request, responder } => {
                    if responder.is_closed() {
                        continue;
                    }
                    if request.network().chain_id() != expected_chain_id
                        || u64::from(request.realm_id()) != expected_realm_id
                        || u64::from(request.realm_sub_id()) != expected_realm_sub_id
                    {
                        let _ = responder.send(Err(
                            RealmProcessorControlError::AuthorityIdentityMismatch,
                        ));
                        return Ok(None);
                    }
                    let outcome = gate
                        .request_drain(request)
                        .map_err(RealmProcessorControlError::Quiescence)?;
                    let acceptance = match outcome {
                        psy_node_core::store::realm_processor_quiescence::RealmProcessorDrainRequestOutcome::Applied(_) => {
                            let snapshot = self.advance(
                                RealmProcessorControlPhase::DrainRequested,
                                Some(request),
                            )?;
                            self.current_request = Some(request);
                            RealmProcessorDrainAcceptance::Applied(snapshot)
                        }
                        psy_node_core::store::realm_processor_quiescence::RealmProcessorDrainRequestOutcome::Idempotent(_) => {
                            RealmProcessorDrainAcceptance::Idempotent(*self.status_tx.borrow())
                        }
                    };
                    let _ = responder.send(Ok(acceptance));
                    return Ok(Some(request));
                }
            }
        }
    }

    pub(super) fn mark_iteration_drained(
        &mut self,
        request: RealmProcessorDrainRequest,
    ) -> Result<(), RealmProcessorControlError> {
        self.require_phase_request(RealmProcessorControlPhase::DrainRequested, request)?;
        self.advance(RealmProcessorControlPhase::IterationDrained, Some(request))?;
        Ok(())
    }

    pub(super) fn mark_gatherer_pause_pending(
        &mut self,
        request: RealmProcessorDrainRequest,
    ) -> Result<(), RealmProcessorControlError> {
        self.require_phase_request(RealmProcessorControlPhase::IterationDrained, request)?;
        self.advance(
            RealmProcessorControlPhase::GathererPausePending,
            Some(request),
        )?;
        Ok(())
    }

    pub(super) fn install_whole_lease(
        &mut self,
        iteration: RealmProcessorIterationDrainedLease,
        gatherer: GathererPauseReceipt,
        request: RealmProcessorDrainRequest,
        pending_context: RealmProcessorPendingContext,
    ) -> Result<(), RealmProcessorControlError> {
        self.require_phase_request(
            RealmProcessorControlPhase::GathererPausePending,
            request,
        )?;
        if iteration.request() != request || gatherer.request().drain_request() != request {
            return Err(RealmProcessorControlError::RequestMismatch);
        }
        if gatherer.unique_id() != pending_context.gathering_proc_unique_id {
            return Err(RealmProcessorControlError::PendingContextMismatch);
        }
        let snapshot = self.advance(RealmProcessorControlPhase::WholeDrained, Some(request))?;
        self.whole_lease = Some(RealmProcessorWholeDrainedLease {
            iteration,
            gatherer,
            request,
            pending_context,
            controller_revision: snapshot.revision,
        });
        Ok(())
    }

    pub(super) fn fail_closed(&mut self, request: RealmProcessorDrainRequest) {
        let _ = self.advance(RealmProcessorControlPhase::FailedClosed, Some(request));
    }

    pub(super) fn is_whole_drained(&self) -> bool {
        let Some(lease) = self.whole_lease.as_ref() else {
            return false;
        };
        // Reading each binding here makes the parked state an ongoing
        // ownership assertion, not merely a boolean latched during install.
        debug_assert_eq!(lease.iteration.request(), lease.request);
        debug_assert_eq!(lease.gatherer.request().drain_request(), lease.request);
        debug_assert_eq!(
            lease.gatherer.unique_id(),
            lease.pending_context.gathering_proc_unique_id
        );
        debug_assert_eq!(
            lease.controller_revision,
            self.status_tx.borrow().revision()
        );
        true
    }

    fn require_phase_request(
        &self,
        phase: RealmProcessorControlPhase,
        request: RealmProcessorDrainRequest,
    ) -> Result<(), RealmProcessorControlError> {
        let snapshot = *self.status_tx.borrow();
        if snapshot.phase != phase {
            return Err(RealmProcessorControlError::UnexpectedPhase);
        }
        if self.current_request != Some(request) {
            return Err(RealmProcessorControlError::RequestMismatch);
        }
        Ok(())
    }

    fn advance(
        &mut self,
        phase: RealmProcessorControlPhase,
        request: Option<RealmProcessorDrainRequest>,
    ) -> Result<RealmProcessorControlSnapshot, RealmProcessorControlError> {
        let current = *self.status_tx.borrow();
        let snapshot = RealmProcessorControlSnapshot {
            revision: current.revision.checked_next()?,
            phase,
            request_digest: request.map(RealmProcessorDrainRequest::digest),
        };
        self.status_tx.send_replace(snapshot);
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use psy_core::constants::chain_id::PsyChainNetworkType;
    use psy_data::protocol::canonical_chain::NetworkId;

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

    #[tokio::test]
    async fn bounded_mailbox_has_one_linearization_owner() {
        let gate = RealmProcessorIterationGate::controlled();
        let (mut owner, handle) = new_realm_processor_control_plane();
        let first_handle = handle.clone();
        let first = tokio::spawn(async move { first_handle.request_drain(request(1)).await });
        tokio::task::yield_now().await;
        assert_eq!(
            handle.request_drain(request(1)).await,
            Err(RealmProcessorControlError::MailboxBusy)
        );
        assert_eq!(
            owner.try_accept_next(&gate, request(1).network().chain_id(), 7, 3)
                .unwrap(),
            Some(request(1))
        );
        assert!(matches!(
            first.await.unwrap().unwrap(),
            RealmProcessorDrainAcceptance::Applied(_)
        ));
        assert_eq!(handle.snapshot().phase(), RealmProcessorControlPhase::DrainRequested);
        assert!(matches!(
            handle.request_drain(request(1)).await.unwrap(),
            RealmProcessorDrainAcceptance::Idempotent(_)
        ));
        assert_eq!(
            handle.request_drain(request(2)).await,
            Err(RealmProcessorControlError::ConflictingRequest)
        );
    }

    #[tokio::test]
    async fn concurrent_request_storm_has_one_applied_owner() {
        let gate = RealmProcessorIterationGate::controlled();
        let (mut owner, handle) = new_realm_processor_control_plane();
        let mut contenders = Vec::new();
        for _ in 0..64 {
            let handle = handle.clone();
            contenders.push(tokio::spawn(async move {
                handle.request_drain(request(1)).await
            }));
        }
        tokio::task::yield_now().await;
        assert_eq!(
            owner.try_accept_next(&gate, request(1).network().chain_id(), 7, 3)
                .unwrap(),
            Some(request(1))
        );

        let mut applied = 0;
        for contender in contenders {
            match contender.await.unwrap() {
                Ok(RealmProcessorDrainAcceptance::Applied(_)) => applied += 1,
                Ok(RealmProcessorDrainAcceptance::Idempotent(_))
                | Err(RealmProcessorControlError::MailboxBusy) => {}
                other => panic!("unexpected contender result: {other:?}"),
            }
        }
        assert_eq!(applied, 1);
        assert_eq!(
            handle.snapshot().phase(),
            RealmProcessorControlPhase::DrainRequested
        );
    }

    #[test]
    fn lost_acceptance_response_does_not_undo_applied_request() {
        let gate = RealmProcessorIterationGate::controlled();
        let (mut owner, handle) = new_realm_processor_control_plane();
        let (responder, response) = oneshot::channel();
        assert!(handle
            .command_tx
            .try_send(RealmProcessorControlCommand::RequestDrain {
                request: request(1),
                responder,
            })
            .is_ok());
        assert_eq!(
            owner.try_accept_next(&gate, request(1).network().chain_id(), 7, 3)
                .unwrap(),
            Some(request(1))
        );
        // The applied ACK is never observed, modeling a response lost after
        // linearization. Actor/gate state must remain drained and retryable.
        drop(response);
        assert_eq!(
            owner.status_tx.borrow().phase(),
            RealmProcessorControlPhase::DrainRequested
        );
        assert_eq!(
            gate.snapshot().phase(),
            psy_node_core::store::realm_processor_quiescence::RealmProcessorQuiescencePhase::DrainRequested
        );
    }

    #[tokio::test]
    async fn caller_cancel_before_dequeue_has_no_effect() {
        let gate = RealmProcessorIterationGate::controlled();
        let (mut owner, handle) = new_realm_processor_control_plane();
        let task = tokio::spawn(async move { handle.request_drain(request(1)).await });
        tokio::task::yield_now().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(
            owner.try_accept_next(&gate, request(1).network().chain_id(), 7, 3)
                .unwrap(),
            None
        );
        assert_eq!(gate.snapshot().phase(), psy_node_core::store::realm_processor_quiescence::RealmProcessorQuiescencePhase::Running);
    }

    #[test]
    fn phase_progression_is_exact_and_revisioned() {
        let gate = RealmProcessorIterationGate::controlled();
        let (mut owner, _handle) = new_realm_processor_control_plane();
        let request = request(1);
        assert!(matches!(
            owner.command_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        owner
            .command_rx
            .close();
        // Exercise the phase guards directly after establishing the same
        // state as an applied command; command acceptance itself is covered
        // by the async test above.
        gate.request_drain(request).unwrap();
        owner.current_request = Some(request);
        owner
            .advance(RealmProcessorControlPhase::DrainRequested, Some(request))
            .unwrap();
        owner.mark_iteration_drained(request).unwrap();
        owner.mark_gatherer_pause_pending(request).unwrap();
        assert_eq!(owner.status_tx.borrow().revision().get(), 3);
        assert_eq!(
            owner.mark_iteration_drained(request),
            Err(RealmProcessorControlError::UnexpectedPhase)
        );
    }

    #[tokio::test]
    async fn wrong_authority_is_rejected_before_gate_mutation() {
        let gate = RealmProcessorIterationGate::controlled();
        let (mut owner, handle) = new_realm_processor_control_plane();
        let requester = tokio::spawn(async move { handle.request_drain(request(1)).await });
        tokio::task::yield_now().await;
        assert_eq!(
            owner
                .try_accept_next(&gate, request(1).network().chain_id(), 8, 3)
                .unwrap(),
            None
        );
        assert_eq!(
            requester.await.unwrap(),
            Err(RealmProcessorControlError::AuthorityIdentityMismatch)
        );
        assert_eq!(
            gate.snapshot().phase(),
            psy_node_core::store::realm_processor_quiescence::RealmProcessorQuiescencePhase::Running
        );
        assert_eq!(
            owner.status_tx.borrow().phase(),
            RealmProcessorControlPhase::Running
        );
    }

    #[test]
    fn pending_context_keeps_processing_and_gathering_axes_distinct() {
        let context = RealmProcessorPendingContext::new(5, 7, 11, 13);
        assert_eq!(context.processing_unique_pending_id(), 5);
        assert_eq!(context.processing_proc_unique_id(), 7);
        assert_eq!(context.gathering_unique_pending_id(), 11);
        assert_eq!(context.gathering_proc_unique_id(), 13);
    }
}
