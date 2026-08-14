//! Durable all-participant convergence for an explicit pre-PONR rollback abort.
//!
//! Rows share the existing append-only rollback archive table.  A Realm may
//! append only its storage-selected paused-runtime acknowledgement.  The
//! Coordinator appends its own acknowledgement, selects every Realm in the
//! immutable participant-plan order, persists one exact barrier, and only
//! then applies `ABORTING -> IDLE`.  This module has no delete API.

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::{NetworkId, CANONICAL_CHAIN_REF_V1_LEN},
    chain_context::AuthorityScope,
};
use psy_node_core::store::{
    canonical_head::{
        CanonicalHeadReadState, CanonicalHeadTransition, CanonicalHeadWriteOutcome,
        StoredCanonicalHead,
    },
    rollback_participant_plan::RollbackParticipantPlan,
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{Consistency, SerialConsistency, prepared::PreparedStatement},
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::{
    CqlKeyspaceName, ScyllaCanonicalHeadStore,
    coordinator_rollback_archive_store::COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE,
};

const ACK_KEY_DOMAIN: i16 = -14;
const BARRIER_KEY_DOMAIN: i16 = -15;
const REVISION: i64 = 1;
const VERSION: u16 = 1;
const ACK_MAGIC: &[u8; 8] = b"PSYRBAK1";
const BARRIER_MAGIC: &[u8; 8] = b"PSYRBAR1";
const STORE_DOMAIN: &[u8] = b"psy.rollback.abort-convergence-store.v1\0";
const ACK_SLOT_DOMAIN: &[u8] = b"psy.rollback.abort-ack-slot.v1\0";
const BARRIER_SLOT_DOMAIN: &[u8] = b"psy.rollback.abort-barrier-slot.v1\0";
const ROW_DIGEST_DOMAIN: &[u8] = b"psy.rollback.abort-row.v1\0";
const FRAGMENT_DOMAIN: &[u8] = b"psy.rollback.abort-fragment.v1\0";
const REALM_SET_DOMAIN: &[u8] = b"psy.rollback.abort-realm-set.v1\0";
const MAX_ROW_BYTES: usize = 16 * 1024;

const INSERT_TEMPLATE: &str = "INSERT INTO {table} (network_chain_id, chain_epoch, participant_plan_digest, key_domain, row_slot, fragment_index, revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) IF NOT EXISTS";
const READ_TEMPLATE: &str = "SELECT fragment_index, revision, fragment_count, row_bytes, fragment_payload, fragment_digest, row_digest FROM {table} WHERE network_chain_id = ? AND chain_epoch = ? AND participant_plan_digest = ? AND key_domain = ? AND row_slot = ?";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PausedRuntimeBoundary {
    revision: u64,
    identity: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredAbortAck<Hash> {
    aborting_head: StoredCanonicalHead<Hash>,
    authority: AuthorityScope,
    plan_digest: [u8; 32],
    paused_runtime: Option<PausedRuntimeBoundary>,
    store_fingerprint: [u8; 32],
    slot: [u8; 32],
    canonical_bytes: Vec<u8>,
    row_digest: [u8; 32],
}

impl<Hash: Q256BitHash> StoredAbortAck<Hash> {
    fn try_new(
        aborting_head: StoredCanonicalHead<Hash>,
        authority: AuthorityScope,
        paused_runtime: Option<PausedRuntimeBoundary>,
        store_fingerprint: [u8; 32],
    ) -> Result<Self, RollbackAbortConvergenceError> {
        let abort = aborting_head
            .rollback_control()
            .aborting()
            .ok_or(RollbackAbortConvergenceError::NotAborting)?;
        if matches!(authority, AuthorityScope::Coordinator) != paused_runtime.is_none()
            || paused_runtime.is_some_and(|runtime| runtime.identity == 0)
        {
            return Err(RollbackAbortConvergenceError::InvalidRuntimeBoundary);
        }
        let plan_digest = *abort.request().plan_digest().as_bytes();
        let slot = ack_slot(&aborting_head, authority, &plan_digest, &store_fingerprint);
        let mut stored = Self {
            aborting_head,
            authority,
            plan_digest,
            paused_runtime,
            store_fingerprint,
            slot,
            canonical_bytes: Vec::new(),
            row_digest: [0; 32],
        };
        stored.canonical_bytes.extend_from_slice(ACK_MAGIC);
        stored.canonical_bytes.extend_from_slice(&VERSION.to_be_bytes());
        stored
            .canonical_bytes
            .extend_from_slice(&encode_authority(authority));
        encode_head(&mut stored.canonical_bytes, &aborting_head)?;
        stored.canonical_bytes.extend_from_slice(&plan_digest);
        match paused_runtime {
            None => stored.canonical_bytes.push(0),
            Some(runtime) => {
                stored.canonical_bytes.push(1);
                stored
                    .canonical_bytes
                    .extend_from_slice(&runtime.revision.to_be_bytes());
                stored
                    .canonical_bytes
                    .extend_from_slice(&runtime.identity.to_be_bytes());
            }
        }
        stored
            .canonical_bytes
            .extend_from_slice(&store_fingerprint);
        stored.canonical_bytes.extend_from_slice(&slot);
        stored.row_digest = row_digest(&stored.canonical_bytes);
        stored
            .canonical_bytes
            .extend_from_slice(&stored.row_digest);
        if stored.canonical_bytes.len() > MAX_ROW_BYTES {
            return Err(RollbackAbortConvergenceError::RowTooLarge);
        }
        Ok(stored)
    }

    fn decode(bytes: &[u8]) -> Result<Self, RollbackAbortConvergenceError> {
        let body = verified_body(bytes)?;
        let mut cursor = Cursor::new(body);
        if cursor.take(8)? != ACK_MAGIC || cursor.u16()? != VERSION {
            return Err(RollbackAbortConvergenceError::MalformedRow);
        }
        let authority = decode_authority(cursor.take(7)?)?;
        let aborting_head = decode_head(&mut cursor)?;
        let plan_digest = cursor.array32()?;
        let paused_runtime = match cursor.u8()? {
            0 => None,
            1 => Some(PausedRuntimeBoundary {
                revision: cursor.u64()?,
                identity: cursor.u128()?,
            }),
            _ => return Err(RollbackAbortConvergenceError::MalformedRow),
        };
        let store_fingerprint = cursor.array32()?;
        let encoded_slot = cursor.array32()?;
        if !cursor.is_empty() {
            return Err(RollbackAbortConvergenceError::TrailingBytes);
        }
        let decoded = Self::try_new(
            aborting_head,
            authority,
            paused_runtime,
            store_fingerprint,
        )?;
        if decoded.plan_digest != plan_digest
            || decoded.slot != encoded_slot
            || decoded.canonical_bytes != bytes
        {
            return Err(RollbackAbortConvergenceError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredAbortBarrier<Hash> {
    aborting_head: StoredCanonicalHead<Hash>,
    plan_digest: [u8; 32],
    coordinator_ack_slot: [u8; 32],
    coordinator_ack_digest: [u8; 32],
    realm_count: u64,
    realm_set_digest: [u8; 32],
    store_fingerprint: [u8; 32],
    slot: [u8; 32],
    canonical_bytes: Vec<u8>,
    row_digest: [u8; 32],
}

impl<Hash: Q256BitHash> StoredAbortBarrier<Hash> {
    fn try_from_acks(
        aborting_head: StoredCanonicalHead<Hash>,
        plan: &RollbackParticipantPlan<Hash>,
        coordinator: &StoredAbortAck<Hash>,
        realms: &[StoredAbortAck<Hash>],
        store_fingerprint: [u8; 32],
    ) -> Result<Self, RollbackAbortConvergenceError> {
        validate_head_plan(&aborting_head, plan)?;
        if coordinator.aborting_head != aborting_head
            || coordinator.authority != AuthorityScope::Coordinator
            || coordinator.paused_runtime.is_some()
            || coordinator.store_fingerprint != store_fingerprint
            || coordinator.plan_digest != *plan.digest()
            || realms.len() != plan.realms().len()
        {
            return Err(RollbackAbortConvergenceError::BindingMismatch);
        }
        let mut set = Sha256::new();
        set.update(REALM_SET_DOMAIN);
        set.update((realms.len() as u64).to_be_bytes());
        for (expected, ack) in plan.realms().iter().zip(realms) {
            let authority = AuthorityScope::Realm {
                realm_id: expected.realm_id(),
                realm_sub_id: expected.realm_sub_id(),
            };
            if ack.aborting_head != aborting_head
                || ack.authority != authority
                || ack.paused_runtime.is_none()
                || ack.store_fingerprint != store_fingerprint
                || ack.plan_digest != *plan.digest()
            {
                return Err(RollbackAbortConvergenceError::BindingMismatch);
            }
            set.update(encode_authority(authority));
            set.update(ack.slot);
            set.update(ack.row_digest);
        }
        Self::try_from_fields(
            aborting_head,
            *plan.digest(),
            coordinator.slot,
            coordinator.row_digest,
            realms.len() as u64,
            set.finalize().into(),
            store_fingerprint,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn try_from_fields(
        aborting_head: StoredCanonicalHead<Hash>,
        plan_digest: [u8; 32],
        coordinator_ack_slot: [u8; 32],
        coordinator_ack_digest: [u8; 32],
        realm_count: u64,
        realm_set_digest: [u8; 32],
        store_fingerprint: [u8; 32],
    ) -> Result<Self, RollbackAbortConvergenceError> {
        let abort = aborting_head
            .rollback_control()
            .aborting()
            .ok_or(RollbackAbortConvergenceError::NotAborting)?;
        if abort.request().plan_digest().as_bytes() != &plan_digest
            || realm_count == 0
            || [
                plan_digest,
                coordinator_ack_slot,
                coordinator_ack_digest,
                realm_set_digest,
                store_fingerprint,
            ]
            .contains(&[0; 32])
        {
            return Err(RollbackAbortConvergenceError::BindingMismatch);
        }
        let slot = barrier_slot(&aborting_head, &plan_digest, &store_fingerprint);
        let mut stored = Self {
            aborting_head,
            plan_digest,
            coordinator_ack_slot,
            coordinator_ack_digest,
            realm_count,
            realm_set_digest,
            store_fingerprint,
            slot,
            canonical_bytes: Vec::new(),
            row_digest: [0; 32],
        };
        stored.canonical_bytes.extend_from_slice(BARRIER_MAGIC);
        stored.canonical_bytes.extend_from_slice(&VERSION.to_be_bytes());
        encode_head(&mut stored.canonical_bytes, &aborting_head)?;
        for field in [
            &plan_digest,
            &coordinator_ack_slot,
            &coordinator_ack_digest,
        ] {
            stored.canonical_bytes.extend_from_slice(field);
        }
        stored
            .canonical_bytes
            .extend_from_slice(&realm_count.to_be_bytes());
        stored
            .canonical_bytes
            .extend_from_slice(&realm_set_digest);
        stored
            .canonical_bytes
            .extend_from_slice(&store_fingerprint);
        stored.canonical_bytes.extend_from_slice(&slot);
        stored.row_digest = row_digest(&stored.canonical_bytes);
        stored
            .canonical_bytes
            .extend_from_slice(&stored.row_digest);
        if stored.canonical_bytes.len() > MAX_ROW_BYTES {
            return Err(RollbackAbortConvergenceError::RowTooLarge);
        }
        Ok(stored)
    }

    fn decode(bytes: &[u8]) -> Result<Self, RollbackAbortConvergenceError> {
        let body = verified_body(bytes)?;
        let mut cursor = Cursor::new(body);
        if cursor.take(8)? != BARRIER_MAGIC || cursor.u16()? != VERSION {
            return Err(RollbackAbortConvergenceError::MalformedRow);
        }
        let aborting_head = decode_head(&mut cursor)?;
        let decoded = Self::try_from_fields(
            aborting_head,
            cursor.array32()?,
            cursor.array32()?,
            cursor.array32()?,
            cursor.u64()?,
            cursor.array32()?,
            cursor.array32()?,
        )?;
        let encoded_slot = cursor.array32()?;
        if !cursor.is_empty()
            || decoded.slot != encoded_slot
            || decoded.canonical_bytes != bytes
        {
            return Err(RollbackAbortConvergenceError::NonCanonicalEncoding);
        }
        Ok(decoded)
    }
}

pub(super) enum RollbackAbortCoordinatorProgress<Hash> {
    AwaitingParticipants {
        head: StoredCanonicalHead<Hash>,
        completed: u64,
        expected: u64,
    },
    Published(StoredCanonicalHead<Hash>),
}

pub(super) struct ScyllaRollbackAbortConvergenceStore {
    session: Arc<Session>,
    fingerprint: [u8; 32],
    insert: PreparedStatement,
    read: PreparedStatement,
}

impl ScyllaRollbackAbortConvergenceStore {
    pub(super) async fn prepare(
        session: Arc<Session>,
        keyspace: &CqlKeyspaceName,
    ) -> Result<Self, RollbackAbortConvergenceError> {
        let table = format!(
            "{}.{}",
            keyspace.as_str(),
            COORDINATOR_ROLLBACK_SUFFIX_ARCHIVE_TABLE
        );
        let insert = INSERT_TEMPLATE.replace("{table}", &table);
        let read = READ_TEMPLATE.replace("{table}", &table);
        let mut hasher = Sha256::new();
        hasher.update(STORE_DOMAIN);
        hasher.update(VERSION.to_be_bytes());
        hasher.update(ACK_MAGIC);
        hasher.update(BARRIER_MAGIC);
        hasher.update(ACK_KEY_DOMAIN.to_be_bytes());
        hasher.update(BARRIER_KEY_DOMAIN.to_be_bytes());
        hasher.update(keyspace.as_str().as_bytes());
        hasher.update(insert.as_bytes());
        hasher.update(read.as_bytes());
        Ok(Self {
            session: session.clone(),
            fingerprint: hasher.finalize().into(),
            insert: prepare_lwt(&session, &insert).await?,
            read: prepare_read(&session, &read).await?,
        })
    }

    pub(super) async fn persist_realm_ack<Hash: Q256BitHash>(
        &self,
        current_head: StoredCanonicalHead<Hash>,
        plan: &RollbackParticipantPlan<Hash>,
        authority: AuthorityScope,
        paused_runtime_revision: u64,
        paused_runtime_identity: u128,
    ) -> Result<(), RollbackAbortConvergenceError> {
        validate_head_plan(&current_head, plan)?;
        let AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } = authority
        else {
            return Err(RollbackAbortConvergenceError::RealmRequired);
        };
        require_realm_participant(plan, realm_id, realm_sub_id)?;
        let expected = StoredAbortAck::try_new(
            current_head,
            authority,
            Some(PausedRuntimeBoundary {
                revision: paused_runtime_revision,
                identity: paused_runtime_identity,
            }),
            self.fingerprint,
        )?;
        self.persist_ack(expected).await.map(|_| ())
    }

    pub(super) async fn progress_coordinator<Hash: Q256BitHash>(
        &self,
        canonical_head: &ScyllaCanonicalHeadStore,
        aborting_head: StoredCanonicalHead<Hash>,
        plan: &RollbackParticipantPlan<Hash>,
    ) -> Result<RollbackAbortCoordinatorProgress<Hash>, RollbackAbortConvergenceError> {
        validate_head_plan(&aborting_head, plan)?;
        let coordinator = self
            .persist_ack(StoredAbortAck::try_new(
                aborting_head,
                AuthorityScope::Coordinator,
                None,
                self.fingerprint,
            )?)
            .await?;
        let mut realms = Vec::with_capacity(plan.realms().len());
        let mut missing = false;
        for participant in plan.realms() {
            let authority = AuthorityScope::Realm {
                realm_id: participant.realm_id(),
                realm_sub_id: participant.realm_sub_id(),
            };
            let slot = ack_slot(
                &aborting_head,
                authority,
                plan.digest(),
                &self.fingerprint,
            );
            match self
                .read_ack(
                    aborting_head.canonical_ref().network_id(),
                    aborting_head.canonical_ref().chain_epoch().get(),
                    plan.digest(),
                    &slot,
                )
                .await?
            {
                Some(ack)
                    if ack.aborting_head == aborting_head
                        && ack.authority == authority
                        && ack.paused_runtime.is_some()
                        && ack.store_fingerprint == self.fingerprint =>
                {
                    realms.push(ack)
                }
                Some(_) => return Err(RollbackAbortConvergenceError::Conflict),
                None => missing = true,
            }
        }
        if missing {
            return Ok(RollbackAbortCoordinatorProgress::AwaitingParticipants {
                head: aborting_head,
                completed: realms.len() as u64,
                expected: plan.realms().len() as u64,
            });
        }
        let barrier = self
            .persist_barrier(StoredAbortBarrier::try_from_acks(
                aborting_head,
                plan,
                &coordinator,
                &realms,
                self.fingerprint,
            )?)
            .await?;
        let current = read_head::<Hash>(canonical_head, aborting_head.canonical_ref().network_id())
            .await?;
        let transition = CanonicalHeadTransition::complete_rollback_abort(aborting_head)
            .map_err(model)?;
        if current == *transition.candidate() {
            self.require_barrier(&barrier).await?;
            return Ok(RollbackAbortCoordinatorProgress::Published(current));
        }
        if current != aborting_head {
            return Err(RollbackAbortConvergenceError::HeadChanged);
        }
        self.require_barrier(&barrier).await?;
        let outcome = canonical_head
            .compare_and_set(&transition.seal())
            .await
            .map_err(backend)?;
        match outcome {
            CanonicalHeadWriteOutcome::Applied(head)
            | CanonicalHeadWriteOutcome::Idempotent(head)
                if head == *transition.candidate() =>
            {
                self.require_barrier(&barrier).await?;
                Ok(RollbackAbortCoordinatorProgress::Published(head))
            }
            _ => Err(RollbackAbortConvergenceError::HeadChanged),
        }
    }

    pub(super) async fn is_published<Hash: Q256BitHash>(
        &self,
        canonical_head: &ScyllaCanonicalHeadStore,
        aborting_head: StoredCanonicalHead<Hash>,
        plan: &RollbackParticipantPlan<Hash>,
        authority: AuthorityScope,
    ) -> Result<bool, RollbackAbortConvergenceError> {
        validate_head_plan(&aborting_head, plan)?;
        let AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } = authority
        else {
            return Err(RollbackAbortConvergenceError::RealmRequired);
        };
        require_realm_participant(plan, realm_id, realm_sub_id)?;
        let slot = ack_slot(
            &aborting_head,
            authority,
            plan.digest(),
            &self.fingerprint,
        );
        let Some(ack) = self
            .read_ack(
                aborting_head.canonical_ref().network_id(),
                aborting_head.canonical_ref().chain_epoch().get(),
                plan.digest(),
                &slot,
            )
            .await?
        else {
            return Ok(false);
        };
        if ack.aborting_head != aborting_head
            || ack.authority != authority
            || ack.paused_runtime.is_none()
            || ack.store_fingerprint != self.fingerprint
        {
            return Err(RollbackAbortConvergenceError::Conflict);
        }
        let barrier_slot = barrier_slot(
            &aborting_head,
            plan.digest(),
            &self.fingerprint,
        );
        let Some(barrier) = self
            .read_barrier::<Hash>(
                aborting_head.canonical_ref().network_id(),
                aborting_head.canonical_ref().chain_epoch().get(),
                plan.digest(),
                &barrier_slot,
            )
            .await?
        else {
            return Ok(false);
        };
        self.require_barrier(&barrier).await?;
        let expected = CanonicalHeadTransition::complete_rollback_abort(aborting_head)
            .map_err(model)?;
        Ok(read_head::<Hash>(canonical_head, aborting_head.canonical_ref().network_id()).await?
            == *expected.candidate())
    }

    async fn persist_ack<Hash: Q256BitHash>(
        &self,
        expected: StoredAbortAck<Hash>,
    ) -> Result<StoredAbortAck<Hash>, RollbackAbortConvergenceError> {
        let execute_error = self.persist_row(&expected, ACK_KEY_DOMAIN).await?;
        let current = self
            .read_ack(
                expected.aborting_head.canonical_ref().network_id(),
                expected.aborting_head.canonical_ref().chain_epoch().get(),
                &expected.plan_digest,
                &expected.slot,
            )
            .await?;
        match current {
            Some(current) if current == expected => Ok(current),
            Some(_) => Err(RollbackAbortConvergenceError::Conflict),
            None => Err(execute_error.map_or(
                RollbackAbortConvergenceError::MissingAfterPersist,
                RollbackAbortConvergenceError::Indeterminate,
            )),
        }
    }

    async fn persist_barrier<Hash: Q256BitHash>(
        &self,
        expected: StoredAbortBarrier<Hash>,
    ) -> Result<StoredAbortBarrier<Hash>, RollbackAbortConvergenceError> {
        let execute_error = self.persist_row(&expected, BARRIER_KEY_DOMAIN).await?;
        let current = self
            .read_barrier(
                expected.aborting_head.canonical_ref().network_id(),
                expected.aborting_head.canonical_ref().chain_epoch().get(),
                &expected.plan_digest,
                &expected.slot,
            )
            .await?;
        match current {
            Some(current) if current == expected => Ok(current),
            Some(_) => Err(RollbackAbortConvergenceError::Conflict),
            None => Err(execute_error.map_or(
                RollbackAbortConvergenceError::MissingAfterPersist,
                RollbackAbortConvergenceError::Indeterminate,
            )),
        }
    }

    async fn require_barrier<Hash: Q256BitHash>(
        &self,
        expected: &StoredAbortBarrier<Hash>,
    ) -> Result<(), RollbackAbortConvergenceError> {
        match self
            .read_barrier(
                expected.aborting_head.canonical_ref().network_id(),
                expected.aborting_head.canonical_ref().chain_epoch().get(),
                &expected.plan_digest,
                &expected.slot,
            )
            .await?
        {
            Some(current) if current == *expected => Ok(()),
            Some(_) => Err(RollbackAbortConvergenceError::Conflict),
            None => Err(RollbackAbortConvergenceError::MissingAfterPersist),
        }
    }

    async fn persist_row<Hash: Q256BitHash, T: AbortRow<Hash>>(
        &self,
        row: &T,
        key_domain: i16,
    ) -> Result<Option<String>, RollbackAbortConvergenceError> {
        let bytes = row.bytes();
        let row_bytes = i64::try_from(bytes.len())
            .map_err(|_| RollbackAbortConvergenceError::LengthOverflow)?;
        let fragment = fragment_digest(row.row_digest(), row_bytes, bytes);
        match self
            .session
            .execute_unpaged(
                &self.insert,
                (
                    i64::from(row.head().canonical_ref().network_id().chain_id()),
                    i64::try_from(row.head().canonical_ref().chain_epoch().get())
                        .map_err(|_| RollbackAbortConvergenceError::IntegerOutOfCqlRange)?,
                    row.plan_digest().as_slice(),
                    key_domain,
                    row.slot().as_slice(),
                    0_i32,
                    REVISION,
                    1_i32,
                    row_bytes,
                    bytes,
                    fragment.as_slice(),
                    row.row_digest().as_slice(),
                ),
            )
            .await
        {
            Ok(result) => {
                let _ = decode_applied(result)?;
                Ok(None)
            }
            Err(error) => Ok(Some(error.to_string())),
        }
    }

    async fn read_ack<Hash: Q256BitHash>(
        &self,
        network: NetworkId,
        epoch: u64,
        plan_digest: &[u8; 32],
        slot: &[u8; 32],
    ) -> Result<Option<StoredAbortAck<Hash>>, RollbackAbortConvergenceError> {
        self.read_row(network, epoch, plan_digest, ACK_KEY_DOMAIN, slot)
            .await?
            .map(|bytes| {
                let decoded = StoredAbortAck::decode(&bytes)?;
                if decoded.slot != *slot || decoded.plan_digest != *plan_digest {
                    return Err(RollbackAbortConvergenceError::Conflict);
                }
                Ok(decoded)
            })
            .transpose()
    }

    async fn read_barrier<Hash: Q256BitHash>(
        &self,
        network: NetworkId,
        epoch: u64,
        plan_digest: &[u8; 32],
        slot: &[u8; 32],
    ) -> Result<Option<StoredAbortBarrier<Hash>>, RollbackAbortConvergenceError> {
        self.read_row(network, epoch, plan_digest, BARRIER_KEY_DOMAIN, slot)
            .await?
            .map(|bytes| {
                let decoded = StoredAbortBarrier::decode(&bytes)?;
                if decoded.slot != *slot || decoded.plan_digest != *plan_digest {
                    return Err(RollbackAbortConvergenceError::Conflict);
                }
                Ok(decoded)
            })
            .transpose()
    }

    async fn read_row(
        &self,
        network: NetworkId,
        epoch: u64,
        plan_digest: &[u8; 32],
        key_domain: i16,
        slot: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, RollbackAbortConvergenceError> {
        let rows = self
            .session
            .execute_unpaged(
                &self.read,
                (
                    i64::from(network.chain_id()),
                    i64::try_from(epoch)
                        .map_err(|_| RollbackAbortConvergenceError::IntegerOutOfCqlRange)?,
                    plan_digest.as_slice(),
                    key_domain,
                    slot.as_slice(),
                ),
            )
            .await
            .map_err(backend)?
            .into_rows_result()
            .map_err(backend)?
            .rows::<(
                Option<i32>,
                Option<i64>,
                Option<i32>,
                Option<i64>,
                Option<Vec<u8>>,
                Option<Vec<u8>>,
                Option<Vec<u8>>,
            )>()
            .map_err(backend)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(backend)?;
        if rows.is_empty() {
            return Ok(None);
        }
        if rows.len() != 1 {
            return Err(RollbackAbortConvergenceError::MalformedRow);
        }
        let (index, revision, count, row_bytes, payload, fragment, digest) =
            rows.into_iter().next().expect("one row");
        let payload = payload.ok_or(RollbackAbortConvergenceError::MalformedRow)?;
        let row_bytes = row_bytes.ok_or(RollbackAbortConvergenceError::MalformedRow)?;
        let fragment: [u8; 32] = fragment
            .ok_or(RollbackAbortConvergenceError::MalformedRow)?
            .try_into()
            .map_err(|_| RollbackAbortConvergenceError::MalformedRow)?;
        let digest: [u8; 32] = digest
            .ok_or(RollbackAbortConvergenceError::MalformedRow)?
            .try_into()
            .map_err(|_| RollbackAbortConvergenceError::MalformedRow)?;
        if index != Some(0)
            || revision != Some(REVISION)
            || count != Some(1)
            || row_bytes <= 0
            || usize::try_from(row_bytes).ok() != Some(payload.len())
            || fragment_digest(&digest, row_bytes, &payload) != fragment
            || payload.len() < 32
            || row_digest(&payload[..payload.len() - 32]) != digest
        {
            return Err(RollbackAbortConvergenceError::MalformedRow);
        }
        Ok(Some(payload))
    }
}

trait AbortRow<Hash> {
    fn head(&self) -> &StoredCanonicalHead<Hash>;
    fn plan_digest(&self) -> &[u8; 32];
    fn slot(&self) -> &[u8; 32];
    fn bytes(&self) -> &[u8];
    fn row_digest(&self) -> &[u8; 32];
}

impl<Hash> AbortRow<Hash> for StoredAbortAck<Hash> {
    fn head(&self) -> &StoredCanonicalHead<Hash> { &self.aborting_head }
    fn plan_digest(&self) -> &[u8; 32] { &self.plan_digest }
    fn slot(&self) -> &[u8; 32] { &self.slot }
    fn bytes(&self) -> &[u8] { &self.canonical_bytes }
    fn row_digest(&self) -> &[u8; 32] { &self.row_digest }
}

impl<Hash> AbortRow<Hash> for StoredAbortBarrier<Hash> {
    fn head(&self) -> &StoredCanonicalHead<Hash> { &self.aborting_head }
    fn plan_digest(&self) -> &[u8; 32] { &self.plan_digest }
    fn slot(&self) -> &[u8; 32] { &self.slot }
    fn bytes(&self) -> &[u8] { &self.canonical_bytes }
    fn row_digest(&self) -> &[u8; 32] { &self.row_digest }
}

fn validate_head_plan<Hash: Q256BitHash>(
    head: &StoredCanonicalHead<Hash>,
    plan: &RollbackParticipantPlan<Hash>,
) -> Result<(), RollbackAbortConvergenceError> {
    let abort = head
        .rollback_control()
        .aborting()
        .ok_or(RollbackAbortConvergenceError::NotAborting)?;
    let plan_request = plan.rollback_request().map_err(model)?;
    if abort.request() != &plan_request
        || abort.request().plan_digest().as_bytes() != plan.digest()
        || head.canonical_ref().network_id() != plan.target().network_id()
        || head.canonical_ref().chain_epoch().get()
            != plan
                .expected_head()
                .canonical_ref()
                .chain_epoch()
                .get()
                .checked_add(1)
                .ok_or(RollbackAbortConvergenceError::BindingMismatch)?
        || head.canonical_ref().checkpoint()
            != plan.expected_head().canonical_ref().checkpoint()
    {
        return Err(RollbackAbortConvergenceError::BindingMismatch);
    }
    Ok(())
}

fn require_realm_participant<Hash: Q256BitHash>(
    plan: &RollbackParticipantPlan<Hash>,
    realm_id: u32,
    realm_sub_id: u16,
) -> Result<(), RollbackAbortConvergenceError> {
    if plan.realms().iter().any(|participant| {
        participant.realm_id() == realm_id && participant.realm_sub_id() == realm_sub_id
    }) {
        Ok(())
    } else {
        Err(RollbackAbortConvergenceError::UnexpectedParticipant)
    }
}

fn ack_slot<Hash: Q256BitHash>(
    head: &StoredCanonicalHead<Hash>,
    authority: AuthorityScope,
    plan_digest: &[u8; 32],
    fingerprint: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ACK_SLOT_DOMAIN);
    hasher.update(head.canonical_ref_bytes());
    hasher.update(head.rollback_control_bytes());
    hasher.update(encode_authority(authority));
    hasher.update(plan_digest);
    hasher.update(fingerprint);
    hasher.finalize().into()
}

fn barrier_slot<Hash: Q256BitHash>(
    head: &StoredCanonicalHead<Hash>,
    plan_digest: &[u8; 32],
    fingerprint: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BARRIER_SLOT_DOMAIN);
    hasher.update(head.canonical_ref_bytes());
    hasher.update(head.rollback_control_bytes());
    hasher.update(plan_digest);
    hasher.update(fingerprint);
    hasher.finalize().into()
}

fn encode_head<Hash: Q256BitHash>(
    out: &mut Vec<u8>,
    head: &StoredCanonicalHead<Hash>,
) -> Result<(), RollbackAbortConvergenceError> {
    out.extend_from_slice(
        &head
            .canonical_ref()
            .network_id()
            .chain_id()
            .to_be_bytes(),
    );
    out.extend_from_slice(&head.revision().as_i64().to_be_bytes());
    out.extend_from_slice(&head.canonical_ref_bytes());
    push_bytes(out, &head.rollback_control_bytes())
}

fn decode_head<Hash: Q256BitHash>(
    cursor: &mut Cursor<'_>,
) -> Result<StoredCanonicalHead<Hash>, RollbackAbortConvergenceError> {
    let network = NetworkId::try_from_chain_id(cursor.u32()?).map_err(model)?;
    let revision = cursor.i64()?;
    let canonical = cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?;
    let control = cursor.bytes()?;
    StoredCanonicalHead::decode_persisted(network, revision, canonical, control).map_err(model)
}

fn encode_authority(authority: AuthorityScope) -> [u8; 7] {
    let mut out = [0; 7];
    match authority {
        AuthorityScope::Coordinator => out[0] = 1,
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => {
            out[0] = 2;
            out[1..5].copy_from_slice(&realm_id.to_be_bytes());
            out[5..7].copy_from_slice(&realm_sub_id.to_be_bytes());
        }
    }
    out
}

fn decode_authority(bytes: &[u8]) -> Result<AuthorityScope, RollbackAbortConvergenceError> {
    match bytes {
        [1, 0, 0, 0, 0, 0, 0] => Ok(AuthorityScope::Coordinator),
        [2, a, b, c, d, e, f] => Ok(AuthorityScope::Realm {
            realm_id: u32::from_be_bytes([*a, *b, *c, *d]),
            realm_sub_id: u16::from_be_bytes([*e, *f]),
        }),
        _ => Err(RollbackAbortConvergenceError::MalformedRow),
    }
}

fn row_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROW_DIGEST_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn fragment_digest(digest: &[u8; 32], row_bytes: i64, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FRAGMENT_DOMAIN);
    hasher.update(digest);
    hasher.update(row_bytes.to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn verified_body(bytes: &[u8]) -> Result<&[u8], RollbackAbortConvergenceError> {
    if bytes.len() < 32 || bytes.len() > MAX_ROW_BYTES {
        return Err(RollbackAbortConvergenceError::MalformedRow);
    }
    let body_len = bytes.len() - 32;
    let digest: [u8; 32] = bytes[body_len..]
        .try_into()
        .expect("32-byte digest");
    if row_digest(&bytes[..body_len]) != digest {
        return Err(RollbackAbortConvergenceError::DigestMismatch);
    }
    Ok(&bytes[..body_len])
}

fn push_bytes(
    out: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), RollbackAbortConvergenceError> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| RollbackAbortConvergenceError::LengthOverflow)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

async fn read_head<Hash: Q256BitHash>(
    store: &ScyllaCanonicalHeadStore,
    network: NetworkId,
) -> Result<StoredCanonicalHead<Hash>, RollbackAbortConvergenceError> {
    match store.read(network).await.map_err(backend)? {
        CanonicalHeadReadState::Current(head) => Ok(head),
        CanonicalHeadReadState::Uninitialized => Err(RollbackAbortConvergenceError::HeadMissing),
    }
}

async fn prepare_lwt(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, RollbackAbortConvergenceError> {
    let mut statement = session.prepare(cql_text).await.map_err(backend)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_read(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, RollbackAbortConvergenceError> {
    let mut statement = session.prepare(cql_text).await.map_err(backend)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(result: QueryResult) -> Result<bool, RollbackAbortConvergenceError> {
    let rows = result
        .into_rows_result()
        .map_err(backend)?;
    let column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(RollbackAbortConvergenceError::MalformedLwtResponse)?;
    let row = rows.single_row::<Row>().map_err(backend)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(applied))) => Ok(*applied),
        _ => Err(RollbackAbortConvergenceError::MalformedLwtResponse),
    }
}

fn model(error: impl fmt::Display) -> RollbackAbortConvergenceError {
    RollbackAbortConvergenceError::Model(error.to_string())
}

fn backend(error: impl fmt::Display) -> RollbackAbortConvergenceError {
    RollbackAbortConvergenceError::Backend(error.to_string())
}

#[derive(Debug)]
pub(super) enum RollbackAbortConvergenceError {
    NotAborting,
    RealmRequired,
    UnexpectedParticipant,
    InvalidRuntimeBoundary,
    BindingMismatch,
    HeadMissing,
    HeadChanged,
    Conflict,
    MissingAfterPersist,
    Indeterminate(String),
    IntegerOutOfCqlRange,
    LengthOverflow,
    RowTooLarge,
    MalformedRow,
    MalformedLwtResponse,
    DigestMismatch,
    NonCanonicalEncoding,
    TrailingBytes,
    Model(String),
    Backend(String),
}

impl fmt::Display for RollbackAbortConvergenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RollbackAbortConvergenceError {}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }
    fn take(&mut self, length: usize) -> Result<&'a [u8], RollbackAbortConvergenceError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(RollbackAbortConvergenceError::MalformedRow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(RollbackAbortConvergenceError::MalformedRow)?;
        self.offset = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, RollbackAbortConvergenceError> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16, RollbackAbortConvergenceError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("2")))
    }
    fn u32(&mut self) -> Result<u32, RollbackAbortConvergenceError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4")))
    }
    fn i64(&mut self) -> Result<i64, RollbackAbortConvergenceError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().expect("8")))
    }
    fn u64(&mut self) -> Result<u64, RollbackAbortConvergenceError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("8")))
    }
    fn u128(&mut self) -> Result<u128, RollbackAbortConvergenceError> {
        Ok(u128::from_be_bytes(self.take(16)?.try_into().expect("16")))
    }
    fn array32(&mut self) -> Result<[u8; 32], RollbackAbortConvergenceError> {
        Ok(self.take(32)?.try_into().expect("32"))
    }
    fn bytes(&mut self) -> Result<&'a [u8], RollbackAbortConvergenceError> {
        let length = self.u32()? as usize;
        self.take(length)
    }
    fn is_empty(&self) -> bool { self.offset == self.bytes.len() }
}

#[cfg(test)]
mod tests {
    use parth_core::data::hash::hash256::Hash256;
    use psy_data::protocol::canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef,
    };
    use psy_node_core::store::{
        canonical_head::{CanonicalHeadTransition, StoredCanonicalHead},
        rollback_control::{
            RollbackAbortReasonCode, RollbackControlState, RollbackExecutionMode,
            RollbackPlanDigest, RollbackRequest,
        },
        rollback_participant_plan::{
            RollbackParticipantPlan, RollbackRealmParticipant,
        },
        timestamp::{CommitWriteTimestampUs, TimestampFenceWindow},
    };

    use super::*;

    type Hash = Hash256;

    fn idle() -> StoredCanonicalHead<Hash> {
        let canonical = CanonicalChainRef::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            ChainEpoch::new(4),
            CheckpointRef::new(
                CheckpointId::new(9),
                CheckpointHash::from_last_chain_hash(Hash256([9; 32])),
            ),
        );
        StoredCanonicalHead::decode_persisted(
            canonical.network_id(),
            0,
            &canonical.to_canonical_bytes(),
            &RollbackControlState::<Hash>::Idle.to_canonical_bytes(),
        )
        .unwrap()
    }

    fn aborting() -> StoredCanonicalHead<Hash> {
        let idle = idle();
        let request = RollbackRequest::try_new(
            *idle.canonical_ref().checkpoint(),
            CheckpointRef::new(
                CheckpointId::new(6),
                CheckpointHash::from_last_chain_hash(Hash256([6; 32])),
            ),
            TimestampFenceWindow::try_new(
                CommitWriteTimestampUs::try_from_i128(100).unwrap(),
                101,
                102,
            )
            .unwrap(),
            RollbackExecutionMode::InPlace,
            RollbackPlanDigest::try_new([7; 32]).unwrap(),
        ).unwrap();
        let requested = *CanonicalHeadTransition::start_rollback(idle, request)
            .unwrap().candidate();
        *CanonicalHeadTransition::begin_rollback_abort(
            requested,
            RollbackAbortReasonCode::try_new(11).unwrap(),
        ).unwrap().candidate()
    }

    fn plan_and_head() -> (RollbackParticipantPlan<Hash>, StoredCanonicalHead<Hash>) {
        let idle = idle();
        let target = CanonicalChainRef::new(
            idle.canonical_ref().network_id(),
            idle.canonical_ref().chain_epoch(),
            CheckpointRef::new(
                CheckpointId::new(6),
                CheckpointHash::from_last_chain_hash(Hash256([6; 32])),
            ),
        );
        let fence = TimestampFenceWindow::try_new(
            CommitWriteTimestampUs::try_from_i128(100).unwrap(),
            101,
            102,
        )
        .unwrap();
        let plan = RollbackParticipantPlan::try_new(
            idle,
            target,
            fence,
            1,
            [8; 32],
            vec![
                RollbackRealmParticipant::new(1, 0),
                RollbackRealmParticipant::new(2, 0),
            ],
        )
        .unwrap();
        let requested = *CanonicalHeadTransition::start_rollback(
            idle,
            plan.rollback_request().unwrap(),
        )
        .unwrap()
        .candidate();
        let head = *CanonicalHeadTransition::begin_rollback_abort(
            requested,
            RollbackAbortReasonCode::try_new(11).unwrap(),
        )
        .unwrap()
        .candidate();
        (plan, head)
    }

    #[test]
    fn ack_codec_binds_exact_abort_and_runtime_boundary() {
        let head = aborting();
        let ack = StoredAbortAck::try_new(
            head,
            AuthorityScope::Realm { realm_id: 1, realm_sub_id: 2 },
            Some(PausedRuntimeBoundary { revision: 3, identity: 4 }),
            [5; 32],
        ).unwrap();
        assert_eq!(StoredAbortAck::<Hash>::decode(&ack.canonical_bytes).unwrap(), ack);
        let mut corrupt = ack.canonical_bytes.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(matches!(
            StoredAbortAck::<Hash>::decode(&corrupt),
            Err(RollbackAbortConvergenceError::DigestMismatch)
        ));
    }

    #[test]
    fn coordinator_ack_cannot_claim_realm_pause_and_realm_requires_identity() {
        let head = aborting();
        assert!(matches!(
            StoredAbortAck::try_new(
                head,
                AuthorityScope::Coordinator,
                Some(PausedRuntimeBoundary { revision: 1, identity: 2 }),
                [3; 32],
            ),
            Err(RollbackAbortConvergenceError::InvalidRuntimeBoundary)
        ));
        assert!(matches!(
            StoredAbortAck::try_new(
                head,
                AuthorityScope::Realm { realm_id: 1, realm_sub_id: 1 },
                Some(PausedRuntimeBoundary { revision: 1, identity: 0 }),
                [3; 32],
            ),
            Err(RollbackAbortConvergenceError::InvalidRuntimeBoundary)
        ));
    }

    #[test]
    fn only_realms_selected_by_the_immutable_plan_can_ack_or_observe() {
        let (plan, _) = plan_and_head();
        assert!(require_realm_participant(&plan, 1, 0).is_ok());
        assert!(matches!(
            require_realm_participant(&plan, 3, 0),
            Err(RollbackAbortConvergenceError::UnexpectedParticipant)
        ));
    }

    #[test]
    fn barrier_binds_coordinator_and_realms_in_fixed_plan_order() {
        let (plan, head) = plan_and_head();
        let fingerprint = [5; 32];
        let coordinator = StoredAbortAck::try_new(
            head,
            AuthorityScope::Coordinator,
            None,
            fingerprint,
        )
        .unwrap();
        let first = StoredAbortAck::try_new(
            head,
            AuthorityScope::Realm {
                realm_id: 1,
                realm_sub_id: 0,
            },
            Some(PausedRuntimeBoundary {
                revision: 3,
                identity: 4,
            }),
            fingerprint,
        )
        .unwrap();
        let second = StoredAbortAck::try_new(
            head,
            AuthorityScope::Realm {
                realm_id: 2,
                realm_sub_id: 0,
            },
            Some(PausedRuntimeBoundary {
                revision: 5,
                identity: 6,
            }),
            fingerprint,
        )
        .unwrap();
        let barrier = StoredAbortBarrier::try_from_acks(
            head,
            &plan,
            &coordinator,
            &[first.clone(), second.clone()],
            fingerprint,
        )
        .unwrap();
        assert_eq!(
            StoredAbortBarrier::<Hash>::decode(&barrier.canonical_bytes).unwrap(),
            barrier
        );
        assert!(matches!(
            StoredAbortBarrier::try_from_acks(
                head,
                &plan,
                &coordinator,
                &[second, first],
                fingerprint,
            ),
            Err(RollbackAbortConvergenceError::BindingMismatch)
        ));
        let idle = CanonicalHeadTransition::complete_rollback_abort(head)
            .unwrap()
            .candidate()
            .to_owned();
        assert!(idle.rollback_control().is_idle());
        assert_eq!(idle.canonical_ref(), head.canonical_ref());
    }

    #[test]
    fn production_slice_has_no_delete_or_runtime_rotation_api() {
        let source = include_str!("rollback_abort_convergence_store.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "delete_suffix",
            "seal_rotation",
            "PendingCounterAdapter",
            "restore_target",
        ] {
            assert!(!production.contains(forbidden));
        }
    }
}
