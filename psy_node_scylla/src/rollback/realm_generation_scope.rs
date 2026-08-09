//! Canonical CQL binding for one Realm pending-generation scope.
//!
//! Queue sidecar tables must share this exact authority encoding.  The global
//! convention is Coordinator=1 and Realm=2; keeping the binder in one module
//! prevents individually self-consistent tables from silently disagreeing.

use std::{error::Error, fmt};

use psy_data::protocol::chain_context::AuthorityScope;
use psy_node_core::queue::recoverable_ephemeral::PendingQueueCaptureContext;

pub(crate) const REALM_AUTHORITY_KIND: i8 = 2;

pub(crate) type RealmGenerationBind =
    (i64, i8, i64, i32, Vec<u8>, i64, Vec<u8>);

pub(crate) fn bind_realm_generation(
    capture: PendingQueueCaptureContext,
) -> Result<RealmGenerationBind, RealmGenerationBindError> {
    let AuthorityScope::Realm {
        realm_id,
        realm_sub_id,
    } = capture.key().authority()
    else {
        return Err(RealmGenerationBindError::RealmOnly);
    };
    Ok((
        i64::from(capture.key().network().chain_id()),
        REALM_AUTHORITY_KIND,
        i64::from(realm_id),
        i32::from(realm_sub_id),
        capture.activation().as_bytes().to_vec(),
        i64::try_from(capture.processing().pending_id().get())
            .map_err(|_| RealmGenerationBindError::PendingOutOfRange)?,
        capture.processing().proc_checkpoint_id().as_bytes().to_vec(),
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RealmGenerationBindError {
    RealmOnly,
    PendingOutOfRange,
}

impl fmt::Display for RealmGenerationBindError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmGenerationBindError {}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_data::protocol::{
        canonical_chain::NetworkId,
        chain_context::AuthorityScope,
    };
    use psy_node_core::store::pending_generation_identity::{
        PendingGenerationActivationDigest, PendingGenerationContext,
        PendingGenerationLedgerKey,
    };

    #[test]
    fn realm_scope_uses_the_global_authority_tag_two() {
        let key = PendingGenerationLedgerKey::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            AuthorityScope::Realm {
                realm_id: 10,
                realm_sub_id: 11,
            },
        );
        let processing = PendingGenerationContext::try_from_legacy(7, 8).unwrap();
        let capture = PendingQueueCaptureContext::try_new(
            key,
            PendingGenerationActivationDigest::try_new([12; 32]).unwrap(),
            processing,
        )
        .unwrap();

        assert_eq!(bind_realm_generation(capture).unwrap().1, REALM_AUTHORITY_KIND);
        assert_eq!(REALM_AUTHORITY_KIND, 2);
    }
}
