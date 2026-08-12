//! Affine installation boundary for the branch-exact Coordinator Processor.
//!
//! The storage factory selects the processing generation.  This owner only
//! seals a process-attempt identity and ensures one mutable Processor
//! iteration can hold one capture port at a time; it deliberately exposes no
//! terminal, rotation, writer or authority-head operation.

use std::{marker::PhantomData, sync::Arc};

use psy_data::protocol::canonical_chain::NetworkId;

use crate::queue::coordinator_processor_durable_capture::{
    CoordinatorProcessorDurableCaptureError,
    CoordinatorProcessorDurableCaptureFactory,
    CoordinatorProcessorDurableCapturePort,
    CoordinatorProcessorDurableCapturedGeneration,
    SealedCoordinatorProcessorDurableCaptureRequest,
};

/// Non-Clone, process-local owner installed from one verified Coordinator
/// sidecar capability.  A fresh process must use a different nonzero attempt
/// digest so stale NATS ownership cannot be silently reused after takeover.
pub struct CoordinatorBranchExactProcessorOwner {
    factory: Arc<dyn CoordinatorProcessorDurableCaptureFactory>,
    owner_attempt_digest: [u8; 32],
}

impl CoordinatorBranchExactProcessorOwner {
    pub fn install(
        factory: Arc<dyn CoordinatorProcessorDurableCaptureFactory>,
        expected_network: NetworkId,
        expected_writer_activation_digest: [u8; 32],
        expected_queue_readiness_digest: [u8; 32],
        owner_attempt_digest: [u8; 32],
    ) -> Result<Self, CoordinatorProcessorDurableCaptureError> {
        if factory.network() != expected_network
            || factory.writer_activation_digest()
                != expected_writer_activation_digest
            || factory.queue_readiness_digest()
                != expected_queue_readiness_digest
            || expected_writer_activation_digest == [0; 32]
            || expected_queue_readiness_digest == [0; 32]
            || owner_attempt_digest == [0; 32]
        {
            return Err(
                CoordinatorProcessorDurableCaptureError::RuntimeCapabilityMismatch,
            );
        }
        Ok(Self {
            factory,
            owner_attempt_digest,
        })
    }

    pub fn network(&self) -> NetworkId {
        self.factory.network()
    }

    pub fn begin_iteration(
        &mut self,
    ) -> CoordinatorBranchExactProcessorIteration<'_> {
        CoordinatorBranchExactProcessorIteration {
            owner: self,
            capture_opened: false,
        }
    }
}

/// Borrowed owner of one Processor iteration.  The mutable borrow prevents a
/// second capture or commit iteration from coexisting in the same process.
pub struct CoordinatorBranchExactProcessorIteration<'owner> {
    owner: &'owner mut CoordinatorBranchExactProcessorOwner,
    capture_opened: bool,
}

impl CoordinatorBranchExactProcessorIteration<'_> {
    pub async fn open_capture<'iteration>(
        &'iteration mut self,
    ) -> Result<CoordinatorBranchExactCapture<'iteration>, CoordinatorProcessorDurableCaptureError>
    {
        if self.capture_opened {
            return Err(CoordinatorProcessorDurableCaptureError::IdentityMismatch);
        }
        self.capture_opened = true;
        let request = SealedCoordinatorProcessorDurableCaptureRequest::seal(
            self.owner.factory.as_ref(),
            self.owner.owner_attempt_digest,
        )?;
        let port = Arc::clone(&self.owner.factory).open(request).await?;
        Ok(CoordinatorBranchExactCapture {
            port,
            _iteration: PhantomData,
        })
    }
}

/// One storage-owned capture port tied to the mutable iteration lifetime.
pub struct CoordinatorBranchExactCapture<'iteration> {
    port: Box<dyn CoordinatorProcessorDurableCapturePort>,
    _iteration: PhantomData<&'iteration mut ()>,
}

impl CoordinatorBranchExactCapture<'_> {
    pub async fn capture_or_replay(
        &mut self,
    ) -> Result<
        Option<CoordinatorProcessorDurableCapturedGeneration>,
        CoordinatorProcessorDurableCaptureError,
    > {
        self.port.capture_or_replay().await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;

    use super::*;

    struct FakeFactory {
        opened: Arc<Mutex<Vec<[u8; 32]>>>,
    }

    struct FakePort;

    #[async_trait]
    impl CoordinatorProcessorDurableCapturePort for FakePort {
        async fn capture_or_replay(
            &mut self,
        ) -> Result<
            Option<CoordinatorProcessorDurableCapturedGeneration>,
            CoordinatorProcessorDurableCaptureError,
        > {
            Ok(None)
        }
    }

    #[async_trait]
    impl CoordinatorProcessorDurableCaptureFactory for FakeFactory {
        fn network(&self) -> NetworkId {
            NetworkId::try_from_chain_id(1337).unwrap()
        }

        fn writer_activation_digest(&self) -> [u8; 32] {
            [7; 32]
        }

        fn queue_readiness_digest(&self) -> [u8; 32] {
            [8; 32]
        }

        async fn open(
            self: Arc<Self>,
            request: SealedCoordinatorProcessorDurableCaptureRequest,
        ) -> Result<
            Box<dyn CoordinatorProcessorDurableCapturePort>,
            CoordinatorProcessorDurableCaptureError,
        > {
            self.opened
                .lock()
                .unwrap()
                .push(*request.owner_attempt_digest());
            Ok(Box::new(FakePort))
        }
    }

    fn factory() -> Arc<FakeFactory> {
        Arc::new(FakeFactory {
            opened: Arc::new(Mutex::new(Vec::new())),
        })
    }

    #[tokio::test]
    async fn installed_owner_opens_storage_capture_with_process_attempt() {
        let factory = factory();
        let trait_factory: Arc<dyn CoordinatorProcessorDurableCaptureFactory> =
            factory.clone();
        let mut owner = CoordinatorBranchExactProcessorOwner::install(
            trait_factory,
            NetworkId::try_from_chain_id(1337).unwrap(),
            [7; 32],
            [8; 32],
            [9; 32],
        )
        .unwrap();
        let mut iteration = owner.begin_iteration();
        let mut capture = iteration.open_capture().await.unwrap();
        assert!(capture.capture_or_replay().await.unwrap().is_none());
        drop(capture);
        assert_eq!(factory.opened.lock().unwrap().as_slice(), &[[9; 32]]);
    }

    #[test]
    fn install_rejects_foreign_or_zero_runtime_identity() {
        let trait_factory: Arc<dyn CoordinatorProcessorDurableCaptureFactory> =
            factory();
        assert!(matches!(
            CoordinatorBranchExactProcessorOwner::install(
                trait_factory,
                NetworkId::try_from_chain_id(1).unwrap(),
                [7; 32],
                [8; 32],
                [9; 32],
            ),
            Err(CoordinatorProcessorDurableCaptureError::RuntimeCapabilityMismatch)
        ));
    }
}
