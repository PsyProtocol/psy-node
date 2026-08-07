//! Shared typed identity for the durable pending pipeline.
//!
//! This module intentionally exposes no identity-only ledger or transition;
//! [`super::pending_generation_pipeline`] is the sole complete state machine.

use std::{error::Error, fmt};

use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};

use super::typed::{ProcCheckpointUniqueId, UniquePendingId};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingGenerationLedgerKey {
    network: NetworkId,
    authority: AuthorityScope,
}

impl PendingGenerationLedgerKey {
    pub const fn new(network: NetworkId, authority: AuthorityScope) -> Self {
        Self { network, authority }
    }

    pub const fn network(self) -> NetworkId {
        self.network
    }

    pub const fn authority(self) -> AuthorityScope {
        self.authority
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingGenerationActivationDigest([u8; 32]);

impl PendingGenerationActivationDigest {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, PendingGenerationIdentityError> {
        if bytes == [0; 32] {
            Err(PendingGenerationIdentityError::EmptyActivationDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingGenerationContext {
    pending_id: UniquePendingId,
    proc_checkpoint_id: ProcCheckpointUniqueId,
}

impl PendingGenerationContext {
    pub fn try_from_legacy(
        pending_id: u64,
        proc_checkpoint_id: u128,
    ) -> Result<Self, PendingGenerationIdentityError> {
        let pending_id = UniquePendingId::try_new(pending_id)
            .map_err(|_| PendingGenerationIdentityError::PendingOutOfRange(pending_id))?;
        if (pending_id.get() == 0) != (proc_checkpoint_id == 0) {
            return Err(PendingGenerationIdentityError::InconsistentZeroContext);
        }
        Ok(Self {
            pending_id,
            proc_checkpoint_id: ProcCheckpointUniqueId::from_u128(proc_checkpoint_id),
        })
    }

    pub const fn pending_id(self) -> UniquePendingId {
        self.pending_id
    }

    pub const fn proc_checkpoint_id(self) -> ProcCheckpointUniqueId {
        self.proc_checkpoint_id
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PendingGenerationBootstrapReason {
    Genesis = 1,
    LegacyActivation = 2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingGenerationIdentityError {
    EmptyActivationDigest,
    PendingOutOfRange(u64),
    InconsistentZeroContext,
}

impl fmt::Display for PendingGenerationIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for PendingGenerationIdentityError {}
