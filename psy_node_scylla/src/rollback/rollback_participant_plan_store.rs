//! Durable deployment topology and exact global rollback participant plans.
//!
//! Topology revisions are append-only and dense.  A participant plan can be
//! persisted only while it exactly matches the greatest durable topology
//! revision before and after the write.  These records remain pre-barrier and
//! grant no deletion, restore, or canonical-head mutation authority.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::NetworkId;
use psy_node_core::store::{
    rollback_participant_plan::RollbackParticipantPlan,
    rollback_topology::RollbackTopologySnapshot,
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::CanonicalHeadNoTabletKeyspace;

pub(crate) const ROLLBACK_TOPOLOGY_HEADER_TABLE: &str =
    "coordinator_rollback_topology_header_v1";
pub(crate) const ROLLBACK_PARTICIPANT_OBJECT_TABLE: &str =
    "coordinator_rollback_participant_object_v1";

const OBJECT_REVISION: i64 = 1;
const TOPOLOGY_DOMAIN: i8 = 1;
const PARTICIPANT_PLAN_DOMAIN: i8 = 2;
const MAX_FRAGMENT_BYTES: usize = 1024 * 1024;
const MAX_FRAGMENTS: usize = 16;
const MAX_OBJECT_BYTES: u64 = (MAX_FRAGMENT_BYTES * MAX_FRAGMENTS) as u64;
const STORE_FINGERPRINT_DOMAIN: &[u8] =
    b"psy.rollback.participant-plan-store.v1\0";
const FRAGMENT_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.participant-plan-fragment.v1\0";

const CREATE_TOPOLOGY_HEADER: &str = "CREATE TABLE IF NOT EXISTS {table} (network_chain_id bigint, topology_revision bigint, topology_digest blob, fragment_count int, object_bytes bigint, PRIMARY KEY ((network_chain_id), topology_revision)) WITH CLUSTERING ORDER BY (topology_revision DESC)";
const CREATE_OBJECT: &str = "CREATE TABLE IF NOT EXISTS {table} (network_chain_id bigint, object_domain tinyint, object_slot blob, fragment_index int, revision bigint, fragment_count int, object_bytes bigint, fragment_payload blob, fragment_digest blob, object_digest blob, PRIMARY KEY ((network_chain_id, object_domain, object_slot), fragment_index)) WITH CLUSTERING ORDER BY (fragment_index ASC)";
const READ_CURRENT_TOPOLOGY_HEADER: &str = "SELECT topology_revision, topology_digest, fragment_count, object_bytes FROM {table} WHERE network_chain_id = ? LIMIT 1";
const READ_EXACT_TOPOLOGY_HEADER: &str = "SELECT topology_revision, topology_digest, fragment_count, object_bytes FROM {table} WHERE network_chain_id = ? AND topology_revision = ?";
const INSERT_TOPOLOGY_HEADER: &str = "INSERT INTO {table} (network_chain_id, topology_revision, topology_digest, fragment_count, object_bytes) VALUES (?, ?, ?, ?, ?) IF NOT EXISTS";
const READ_OBJECT: &str = "SELECT fragment_index, revision, fragment_count, object_bytes, fragment_payload, fragment_digest, object_digest FROM {table} WHERE network_chain_id = ? AND object_domain = ? AND object_slot = ?";
const READ_OBJECT_FRAGMENT: &str = "SELECT revision, fragment_count, object_bytes, fragment_payload, fragment_digest, object_digest FROM {table} WHERE network_chain_id = ? AND object_domain = ? AND object_slot = ? AND fragment_index = ?";
const INSERT_OBJECT_FRAGMENT: &str = "INSERT INTO {table} (network_chain_id, object_domain, object_slot, fragment_index, revision, fragment_count, object_bytes, fragment_payload, fragment_digest, object_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) IF NOT EXISTS";

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParticipantPlanQueries {
    create_topology_header: String,
    create_object: String,
    read_current_topology_header: String,
    read_exact_topology_header: String,
    insert_topology_header: String,
    read_object: String,
    read_object_fragment: String,
    insert_object_fragment: String,
}

impl ParticipantPlanQueries {
    fn new(keyspace: &CanonicalHeadNoTabletKeyspace) -> Self {
        let topology = format!(
            "{}.{}",
            keyspace.as_str(),
            ROLLBACK_TOPOLOGY_HEADER_TABLE
        );
        let object = format!(
            "{}.{}",
            keyspace.as_str(),
            ROLLBACK_PARTICIPANT_OBJECT_TABLE
        );
        Self {
            create_topology_header: CREATE_TOPOLOGY_HEADER.replace("{table}", &topology),
            create_object: CREATE_OBJECT.replace("{table}", &object),
            read_current_topology_header: READ_CURRENT_TOPOLOGY_HEADER
                .replace("{table}", &topology),
            read_exact_topology_header: READ_EXACT_TOPOLOGY_HEADER
                .replace("{table}", &topology),
            insert_topology_header: INSERT_TOPOLOGY_HEADER.replace("{table}", &topology),
            read_object: READ_OBJECT.replace("{table}", &object),
            read_object_fragment: READ_OBJECT_FRAGMENT.replace("{table}", &object),
            insert_object_fragment: INSERT_OBJECT_FRAGMENT.replace("{table}", &object),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TopologyHeader {
    revision: u64,
    digest: [u8; 32],
    fragment_count: u32,
    object_bytes: u64,
}

#[derive(Debug)]
pub(crate) struct PersistedRollbackTopologyReceipt {
    store_fingerprint: [u8; 32],
    header: TopologyHeader,
    snapshot: RollbackTopologySnapshot,
}

impl PersistedRollbackTopologyReceipt {
    pub(crate) const fn snapshot(&self) -> &RollbackTopologySnapshot {
        &self.snapshot
    }
}

#[derive(Debug)]
pub(crate) struct PersistedRollbackParticipantPlanReceipt<Hash> {
    store_fingerprint: [u8; 32],
    topology_revision: u64,
    topology_digest: [u8; 32],
    plan: RollbackParticipantPlan<Hash>,
}

impl<Hash: Q256BitHash> PersistedRollbackParticipantPlanReceipt<Hash> {
    pub(crate) const fn plan(&self) -> &RollbackParticipantPlan<Hash> {
        &self.plan
    }
}

pub(crate) struct ScyllaRollbackParticipantPlanStore {
    session: Arc<Session>,
    queries: ParticipantPlanQueries,
    read_current_topology_header: PreparedStatement,
    read_exact_topology_header: PreparedStatement,
    insert_topology_header: PreparedStatement,
    read_object: PreparedStatement,
    read_object_fragment: PreparedStatement,
    insert_object_fragment: PreparedStatement,
    fingerprint: [u8; 32],
}

impl ScyllaRollbackParticipantPlanStore {
    pub(crate) async fn create_schema(
        session: &Session,
        keyspace: &CanonicalHeadNoTabletKeyspace,
    ) -> Result<(), RollbackParticipantStoreError> {
        let queries = ParticipantPlanQueries::new(keyspace);
        session
            .query_unpaged(queries.create_topology_header.as_str(), &[])
            .await
            .map_err(cql_error)?;
        session
            .query_unpaged(queries.create_object.as_str(), &[])
            .await
            .map_err(cql_error)?;
        session.await_schema_agreement().await.map_err(cql_error)?;
        Ok(())
    }

    pub(crate) async fn prepare(
        session: Arc<Session>,
        keyspace: CanonicalHeadNoTabletKeyspace,
    ) -> Result<Self, RollbackParticipantStoreError> {
        let queries = ParticipantPlanQueries::new(&keyspace);
        let read_current_topology_header =
            prepare_read(&session, &queries.read_current_topology_header).await?;
        let read_exact_topology_header =
            prepare_read(&session, &queries.read_exact_topology_header).await?;
        let insert_topology_header =
            prepare_lwt(&session, &queries.insert_topology_header).await?;
        let read_object = prepare_read(&session, &queries.read_object).await?;
        let read_object_fragment =
            prepare_read(&session, &queries.read_object_fragment).await?;
        let insert_object_fragment =
            prepare_lwt(&session, &queries.insert_object_fragment).await?;
        let fingerprint = store_fingerprint(keyspace.as_str());
        Ok(Self {
            session,
            queries,
            read_current_topology_header,
            read_exact_topology_header,
            insert_topology_header,
            read_object,
            read_object_fragment,
            insert_object_fragment,
            fingerprint,
        })
    }

    /// Deployment-management seam.  Rollback RPCs do not receive this API.
    pub(crate) async fn install_next_topology(
        &self,
        snapshot: &RollbackTopologySnapshot,
    ) -> Result<PersistedRollbackTopologyReceipt, RollbackParticipantStoreError> {
        let current = self.read_current_topology(snapshot.network()).await?;
        if let Some(current) = current.as_ref() {
            if current.snapshot == *snapshot {
                return self.read_topology_at(snapshot.network(), current.header).await;
            }
        }
        let before = current.as_ref().map(|current| current.header);
        let expected_revision = match before {
            None => 0,
            Some(current) => current
                .revision
                .checked_add(1)
                .ok_or(RollbackParticipantStoreError::TopologyRevisionOverflow)?,
        };
        if snapshot.revision() != expected_revision {
            return Err(RollbackParticipantStoreError::TopologyRevisionNotNext {
                expected: expected_revision,
                candidate: snapshot.revision(),
            });
        }
        let header = object_header(snapshot.canonical_bytes(), *snapshot.digest())?;
        self.persist_object(
            snapshot.network(),
            TOPOLOGY_DOMAIN,
            snapshot.digest(),
            snapshot.canonical_bytes(),
        )
        .await?;
        if self.read_current_topology_header(snapshot.network()).await? != before {
            return Err(RollbackParticipantStoreError::ConcurrentTopologyChange);
        }
        let execution = self
            .session
            .execute_unpaged(
                &self.insert_topology_header,
                TopologyHeaderInsertBinding {
                    network_chain_id: i64::from(snapshot.network().chain_id()),
                    topology_revision: u64_to_i64(snapshot.revision())?,
                    topology_digest: snapshot.digest().to_vec(),
                    fragment_count: u32_to_i32(header.fragment_count)?,
                    object_bytes: u64_to_i64(header.object_bytes)?,
                },
            )
            .await;
        self.finish_topology_header_write(snapshot, header, execution)
            .await
    }

    pub(crate) async fn read_current_topology(
        &self,
        network: NetworkId,
    ) -> Result<Option<PersistedRollbackTopologyReceipt>, RollbackParticipantStoreError> {
        let Some(header) = self.read_current_topology_header(network).await? else {
            return Ok(None);
        };
        self.read_topology_at(network, header).await.map(Some)
    }

    pub(crate) async fn persist_participant_plan<Hash: Q256BitHash>(
        &self,
        plan: &RollbackParticipantPlan<Hash>,
    ) -> Result<PersistedRollbackParticipantPlanReceipt<Hash>, RollbackParticipantStoreError> {
        let network = plan.expected_head().canonical_ref().network_id();
        let topology = self
            .read_current_topology(network)
            .await?
            .ok_or(RollbackParticipantStoreError::TopologyMissing)?;
        if !topology.snapshot.validates_plan(plan) {
            return Err(RollbackParticipantStoreError::PlanTopologyMismatch);
        }
        self.persist_object(
            network,
            PARTICIPANT_PLAN_DOMAIN,
            plan.digest(),
            plan.canonical_bytes(),
        )
        .await?;
        let after = self
            .read_current_topology(network)
            .await?
            .ok_or(RollbackParticipantStoreError::TopologyMissing)?;
        if topology.header != after.header || topology.snapshot != after.snapshot {
            return Err(RollbackParticipantStoreError::ConcurrentTopologyChange);
        }
        let stored = self.read_participant_plan(network, plan.digest()).await?;
        if &stored != plan {
            return Err(RollbackParticipantStoreError::ObjectConflict);
        }
        Ok(PersistedRollbackParticipantPlanReceipt {
            store_fingerprint: self.fingerprint,
            topology_revision: topology.header.revision,
            topology_digest: topology.header.digest,
            plan: stored,
        })
    }

    pub(crate) async fn revalidate_participant_plan<Hash: Q256BitHash>(
        &self,
        receipt: &PersistedRollbackParticipantPlanReceipt<Hash>,
    ) -> Result<(), RollbackParticipantStoreError> {
        if receipt.store_fingerprint != self.fingerprint {
            return Err(RollbackParticipantStoreError::StoreFingerprintMismatch);
        }
        let network = receipt.plan.expected_head().canonical_ref().network_id();
        let topology = self
            .read_current_topology(network)
            .await?
            .ok_or(RollbackParticipantStoreError::TopologyMissing)?;
        if topology.header.revision != receipt.topology_revision
            || topology.header.digest != receipt.topology_digest
            || !topology.snapshot.validates_plan(&receipt.plan)
        {
            return Err(RollbackParticipantStoreError::ConcurrentTopologyChange);
        }
        let stored = self
            .read_participant_plan(network, receipt.plan.digest())
            .await?;
        if stored != receipt.plan {
            return Err(RollbackParticipantStoreError::ObjectConflict);
        }
        Ok(())
    }

    pub(crate) async fn read_participant_plan<Hash: Q256BitHash>(
        &self,
        network: NetworkId,
        digest: &[u8; 32],
    ) -> Result<RollbackParticipantPlan<Hash>, RollbackParticipantStoreError> {
        let bytes = self
            .read_object_bytes(network, PARTICIPANT_PLAN_DOMAIN, digest)
            .await?
            .ok_or(RollbackParticipantStoreError::ObjectMissing)?;
        let plan = RollbackParticipantPlan::decode_canonical(&bytes)
            .map_err(|error| RollbackParticipantStoreError::Codec(error.to_string()))?;
        if plan.digest() != digest {
            return Err(RollbackParticipantStoreError::ObjectDigestMismatch);
        }
        Ok(plan)
    }

    async fn finish_topology_header_write(
        &self,
        snapshot: &RollbackTopologySnapshot,
        expected: ObjectHeader,
        execution: Result<QueryResult, scylla::errors::ExecutionError>,
    ) -> Result<PersistedRollbackTopologyReceipt, RollbackParticipantStoreError> {
        match execution {
            Ok(result) => {
                let _applied = decode_lwt_applied(result)?;
            }
            Err(execute_error) => {
                let current = self
                    .read_exact_topology_header(snapshot.network(), snapshot.revision())
                    .await;
                match current {
                    Ok(Some(header))
                        if header.digest == *snapshot.digest()
                            && header.fragment_count == expected.fragment_count
                            && header.object_bytes == expected.object_bytes => {}
                    Ok(_) => {
                        return Err(RollbackParticipantStoreError::IndeterminateWrite(
                            execute_error.to_string(),
                        ));
                    }
                    Err(read_error) => {
                        return Err(RollbackParticipantStoreError::IndeterminateReadFailed {
                            execute_error: execute_error.to_string(),
                            read_error: read_error.to_string(),
                        });
                    }
                }
            }
        }
        let header = self
            .read_exact_topology_header(snapshot.network(), snapshot.revision())
            .await?
            .ok_or(RollbackParticipantStoreError::ObjectMissing)?;
        if header.digest != *snapshot.digest()
            || header.fragment_count != expected.fragment_count
            || header.object_bytes != expected.object_bytes
        {
            return Err(RollbackParticipantStoreError::ObjectConflict);
        }
        self.read_topology_at(snapshot.network(), header).await
    }

    async fn read_topology_at(
        &self,
        network: NetworkId,
        header: TopologyHeader,
    ) -> Result<PersistedRollbackTopologyReceipt, RollbackParticipantStoreError> {
        let bytes = self
            .read_object_bytes(network, TOPOLOGY_DOMAIN, &header.digest)
            .await?
            .ok_or(RollbackParticipantStoreError::ObjectMissing)?;
        let snapshot = RollbackTopologySnapshot::decode_canonical(&bytes)
            .map_err(|error| RollbackParticipantStoreError::Codec(error.to_string()))?;
        if snapshot.network() != network
            || snapshot.revision() != header.revision
            || snapshot.digest() != &header.digest
            || bytes.len() as u64 != header.object_bytes
        {
            return Err(RollbackParticipantStoreError::ObjectConflict);
        }
        let rebuilt_header = object_header(&bytes, header.digest)?;
        if rebuilt_header.fragment_count != header.fragment_count
            || rebuilt_header.object_bytes != header.object_bytes
        {
            return Err(RollbackParticipantStoreError::ObjectConflict);
        }
        Ok(PersistedRollbackTopologyReceipt {
            store_fingerprint: self.fingerprint,
            header,
            snapshot,
        })
    }

    async fn persist_object(
        &self,
        network: NetworkId,
        domain: i8,
        slot: &[u8; 32],
        bytes: &[u8],
    ) -> Result<(), RollbackParticipantStoreError> {
        let header = object_header(bytes, *slot)?;
        for (index, payload) in bytes.chunks(MAX_FRAGMENT_BYTES).enumerate() {
            let fragment = StoredObjectFragment {
                revision: OBJECT_REVISION,
                fragment_count: header.fragment_count,
                object_bytes: header.object_bytes,
                payload: payload.to_vec(),
                fragment_digest: fragment_digest(index as u32, payload),
                object_digest: *slot,
            };
            let binding = ObjectFragmentInsertBinding {
                network_chain_id: i64::from(network.chain_id()),
                object_domain: domain,
                object_slot: slot.to_vec(),
                fragment_index: usize_to_i32(index)?,
                revision: fragment.revision,
                fragment_count: u32_to_i32(fragment.fragment_count)?,
                object_bytes: u64_to_i64(fragment.object_bytes)?,
                fragment_payload: fragment.payload.clone(),
                fragment_digest: fragment.fragment_digest.to_vec(),
                object_digest: fragment.object_digest.to_vec(),
            };
            let execution = self
                .session
                .execute_unpaged(&self.insert_object_fragment, binding)
                .await;
            match execution {
                Ok(result) => {
                    let _applied = decode_lwt_applied(result)?;
                }
                Err(execute_error) => match self
                    .read_object_fragment(network, domain, slot, index as u32)
                    .await
                {
                    Ok(Some(current)) if current == fragment => {}
                    Ok(_) => {
                        return Err(RollbackParticipantStoreError::IndeterminateWrite(
                            execute_error.to_string(),
                        ));
                    }
                    Err(read_error) => {
                        return Err(RollbackParticipantStoreError::IndeterminateReadFailed {
                            execute_error: execute_error.to_string(),
                            read_error: read_error.to_string(),
                        });
                    }
                },
            }
            let stored = self
                .read_object_fragment(network, domain, slot, index as u32)
                .await?
                .ok_or(RollbackParticipantStoreError::ObjectMissing)?;
            if stored != fragment {
                return Err(RollbackParticipantStoreError::ObjectConflict);
            }
        }
        let stored = self
            .read_object_bytes(network, domain, slot)
            .await?
            .ok_or(RollbackParticipantStoreError::ObjectMissing)?;
        if stored != bytes {
            return Err(RollbackParticipantStoreError::ObjectConflict);
        }
        Ok(())
    }

    async fn read_object_bytes(
        &self,
        network: NetworkId,
        domain: i8,
        slot: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, RollbackParticipantStoreError> {
        let result = self
            .session
            .execute_unpaged(
                &self.read_object,
                ObjectReadBinding {
                    network_chain_id: i64::from(network.chain_id()),
                    object_domain: domain,
                    object_slot: slot.to_vec(),
                },
            )
            .await
            .map_err(cql_error)?;
        let rows = result
            .into_rows_result()
            .map_err(cql_error)?
            .rows::<ObjectDbRow>()
            .map_err(cql_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(cql_error)?;
        if rows.is_empty() {
            return Ok(None);
        }
        let mut fragments = Vec::with_capacity(rows.len());
        for row in rows {
            fragments.push(decode_object_row(row)?);
        }
        Ok(Some(reconstruct_object(fragments, slot)?))
    }

    async fn read_object_fragment(
        &self,
        network: NetworkId,
        domain: i8,
        slot: &[u8; 32],
        index: u32,
    ) -> Result<Option<StoredObjectFragment>, RollbackParticipantStoreError> {
        let result = self
            .session
            .execute_unpaged(
                &self.read_object_fragment,
                ObjectFragmentReadBinding {
                    network_chain_id: i64::from(network.chain_id()),
                    object_domain: domain,
                    object_slot: slot.to_vec(),
                    fragment_index: u32_to_i32(index)?,
                },
            )
            .await
            .map_err(cql_error)?;
        result
            .into_rows_result()
            .map_err(cql_error)?
            .maybe_first_row::<ObjectFragmentDbRow>()
            .map_err(cql_error)?
            .map(decode_object_fragment_row)
            .transpose()
    }

    async fn read_current_topology_header(
        &self,
        network: NetworkId,
    ) -> Result<Option<TopologyHeader>, RollbackParticipantStoreError> {
        self.read_topology_header(
            &self.read_current_topology_header,
            TopologyCurrentReadBinding {
                network_chain_id: i64::from(network.chain_id()),
            },
        )
        .await
    }

    async fn read_exact_topology_header(
        &self,
        network: NetworkId,
        revision: u64,
    ) -> Result<Option<TopologyHeader>, RollbackParticipantStoreError> {
        self.read_topology_header(
            &self.read_exact_topology_header,
            TopologyExactReadBinding {
                network_chain_id: i64::from(network.chain_id()),
                topology_revision: u64_to_i64(revision)?,
            },
        )
        .await
    }

    async fn read_topology_header<V: scylla::serialize::row::SerializeRow>(
        &self,
        statement: &PreparedStatement,
        values: V,
    ) -> Result<Option<TopologyHeader>, RollbackParticipantStoreError> {
        let row = self
            .session
            .execute_unpaged(statement, values)
            .await
            .map_err(cql_error)?
            .into_rows_result()
            .map_err(cql_error)?
            .maybe_first_row::<TopologyHeaderDbRow>()
            .map_err(cql_error)?;
        row.map(decode_topology_header).transpose()
    }
}

#[derive(Clone, Copy)]
struct ObjectHeader {
    fragment_count: u32,
    object_bytes: u64,
}

fn object_header(bytes: &[u8], digest: [u8; 32]) -> Result<ObjectHeader, RollbackParticipantStoreError> {
    if bytes.is_empty() || digest == [0; 32] {
        return Err(RollbackParticipantStoreError::InvalidObject);
    }
    let fragment_count = bytes.len().div_ceil(MAX_FRAGMENT_BYTES);
    if fragment_count == 0 || fragment_count > MAX_FRAGMENTS {
        return Err(RollbackParticipantStoreError::InvalidFragmentCount(fragment_count));
    }
    Ok(ObjectHeader {
        fragment_count: u32::try_from(fragment_count)
            .map_err(|_| RollbackParticipantStoreError::NumericOverflow)?,
        object_bytes: u64::try_from(bytes.len())
            .map_err(|_| RollbackParticipantStoreError::NumericOverflow)?,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredObjectFragment {
    revision: i64,
    fragment_count: u32,
    object_bytes: u64,
    payload: Vec<u8>,
    fragment_digest: [u8; 32],
    object_digest: [u8; 32],
}

fn reconstruct_object(
    mut fragments: Vec<(u32, StoredObjectFragment)>,
    expected_digest: &[u8; 32],
) -> Result<Vec<u8>, RollbackParticipantStoreError> {
    fragments.sort_unstable_by_key(|(index, _)| *index);
    let first = fragments
        .first()
        .ok_or(RollbackParticipantStoreError::ObjectMissing)?
        .1
        .clone();
    if first.fragment_count as usize != fragments.len()
        || first.fragment_count == 0
        || first.fragment_count as usize > MAX_FRAGMENTS
        || first.object_bytes == 0
        || first.object_bytes > MAX_OBJECT_BYTES
        || first.object_digest != *expected_digest
    {
        return Err(RollbackParticipantStoreError::InvalidObject);
    }
    let mut bytes = Vec::with_capacity(first.object_bytes as usize);
    for (position, (index, fragment)) in fragments.into_iter().enumerate() {
        if index as usize != position
            || fragment.revision != OBJECT_REVISION
            || fragment.fragment_count != first.fragment_count
            || fragment.object_bytes != first.object_bytes
            || fragment.object_digest != first.object_digest
            || fragment.payload.is_empty()
            || fragment.payload.len() > MAX_FRAGMENT_BYTES
            || fragment.fragment_digest != fragment_digest(index, &fragment.payload)
        {
            return Err(RollbackParticipantStoreError::InvalidObject);
        }
        bytes.extend_from_slice(&fragment.payload);
    }
    if bytes.len() as u64 != first.object_bytes {
        return Err(RollbackParticipantStoreError::InvalidObject);
    }
    Ok(bytes)
}

fn fragment_digest(index: u32, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FRAGMENT_DIGEST_DOMAIN);
    hasher.update(index.to_be_bytes());
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn store_fingerprint(keyspace: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(STORE_FINGERPRINT_DOMAIN);
    hasher.update((keyspace.len() as u64).to_be_bytes());
    hasher.update(keyspace.as_bytes());
    hasher.update(ROLLBACK_TOPOLOGY_HEADER_TABLE.as_bytes());
    hasher.update(ROLLBACK_PARTICIPANT_OBJECT_TABLE.as_bytes());
    hasher.finalize().into()
}

async fn prepare_read(
    session: &Session,
    cql: &str,
) -> Result<PreparedStatement, RollbackParticipantStoreError> {
    let mut statement = session.prepare(cql).await.map_err(cql_error)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql: &str,
) -> Result<PreparedStatement, RollbackParticipantStoreError> {
    let mut statement = session.prepare(cql).await.map_err(cql_error)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_lwt_applied(result: QueryResult) -> Result<bool, RollbackParticipantStoreError> {
    let rows = result.into_rows_result().map_err(cql_error)?;
    let column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(RollbackParticipantStoreError::InvalidApplied)?;
    let row = rows.single_row::<Row>().map_err(cql_error)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(applied))) => Ok(*applied),
        _ => Err(RollbackParticipantStoreError::InvalidApplied),
    }
}

#[derive(scylla::DeserializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct TopologyHeaderDbRow {
    topology_revision: i64,
    topology_digest: Vec<u8>,
    fragment_count: i32,
    object_bytes: i64,
}

#[derive(scylla::DeserializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct ObjectDbRow {
    fragment_index: i32,
    revision: i64,
    fragment_count: i32,
    object_bytes: i64,
    fragment_payload: Vec<u8>,
    fragment_digest: Vec<u8>,
    object_digest: Vec<u8>,
}

#[derive(scylla::DeserializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct ObjectFragmentDbRow {
    revision: i64,
    fragment_count: i32,
    object_bytes: i64,
    fragment_payload: Vec<u8>,
    fragment_digest: Vec<u8>,
    object_digest: Vec<u8>,
}

fn decode_topology_header(row: TopologyHeaderDbRow) -> Result<TopologyHeader, RollbackParticipantStoreError> {
    Ok(TopologyHeader {
        revision: i64_to_u64(row.topology_revision)?,
        digest: vec_to_digest(row.topology_digest)?,
        fragment_count: i32_to_u32(row.fragment_count)?,
        object_bytes: i64_to_u64(row.object_bytes)?,
    })
}

fn decode_object_row(row: ObjectDbRow) -> Result<(u32, StoredObjectFragment), RollbackParticipantStoreError> {
    Ok((
        i32_to_u32(row.fragment_index)?,
        StoredObjectFragment {
            revision: row.revision,
            fragment_count: i32_to_u32(row.fragment_count)?,
            object_bytes: i64_to_u64(row.object_bytes)?,
            payload: row.fragment_payload,
            fragment_digest: vec_to_digest(row.fragment_digest)?,
            object_digest: vec_to_digest(row.object_digest)?,
        },
    ))
}

fn decode_object_fragment_row(row: ObjectFragmentDbRow) -> Result<StoredObjectFragment, RollbackParticipantStoreError> {
    Ok(StoredObjectFragment {
        revision: row.revision,
        fragment_count: i32_to_u32(row.fragment_count)?,
        object_bytes: i64_to_u64(row.object_bytes)?,
        payload: row.fragment_payload,
        fragment_digest: vec_to_digest(row.fragment_digest)?,
        object_digest: vec_to_digest(row.object_digest)?,
    })
}

#[derive(scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct TopologyCurrentReadBinding { network_chain_id: i64 }
#[derive(scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct TopologyExactReadBinding { network_chain_id: i64, topology_revision: i64 }
#[derive(scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct TopologyHeaderInsertBinding { network_chain_id: i64, topology_revision: i64, topology_digest: Vec<u8>, fragment_count: i32, object_bytes: i64 }
#[derive(scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct ObjectReadBinding { network_chain_id: i64, object_domain: i8, object_slot: Vec<u8> }
#[derive(scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct ObjectFragmentReadBinding { network_chain_id: i64, object_domain: i8, object_slot: Vec<u8>, fragment_index: i32 }
#[derive(scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct ObjectFragmentInsertBinding { network_chain_id: i64, object_domain: i8, object_slot: Vec<u8>, fragment_index: i32, revision: i64, fragment_count: i32, object_bytes: i64, fragment_payload: Vec<u8>, fragment_digest: Vec<u8>, object_digest: Vec<u8> }

fn vec_to_digest(value: Vec<u8>) -> Result<[u8; 32], RollbackParticipantStoreError> {
    value.try_into().map_err(|_| RollbackParticipantStoreError::InvalidObject)
}
fn u64_to_i64(value: u64) -> Result<i64, RollbackParticipantStoreError> { i64::try_from(value).map_err(|_| RollbackParticipantStoreError::NumericOverflow) }
fn i64_to_u64(value: i64) -> Result<u64, RollbackParticipantStoreError> { u64::try_from(value).map_err(|_| RollbackParticipantStoreError::NumericOverflow) }
fn u32_to_i32(value: u32) -> Result<i32, RollbackParticipantStoreError> { i32::try_from(value).map_err(|_| RollbackParticipantStoreError::NumericOverflow) }
fn i32_to_u32(value: i32) -> Result<u32, RollbackParticipantStoreError> { u32::try_from(value).map_err(|_| RollbackParticipantStoreError::NumericOverflow) }
fn usize_to_i32(value: usize) -> Result<i32, RollbackParticipantStoreError> { i32::try_from(value).map_err(|_| RollbackParticipantStoreError::NumericOverflow) }
fn cql_error(error: impl fmt::Display) -> RollbackParticipantStoreError { RollbackParticipantStoreError::Cql(error.to_string()) }

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RollbackParticipantStoreError {
    Cql(String), Codec(String), NumericOverflow, InvalidApplied, InvalidObject,
    InvalidFragmentCount(usize), ObjectMissing, ObjectConflict, ObjectDigestMismatch,
    TopologyMissing, PlanTopologyMismatch, StoreFingerprintMismatch,
    TopologyRevisionOverflow, TopologyRevisionNotNext { expected: u64, candidate: u64 },
    ConcurrentTopologyChange, IndeterminateWrite(String),
    IndeterminateReadFailed { execute_error: String, read_error: String },
}

impl fmt::Display for RollbackParticipantStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "rollback participant store failed: {self:?}")
    }
}
impl Error for RollbackParticipantStoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_are_append_only_quorum_lwt_contracts() {
        let keyspace = CanonicalHeadNoTabletKeyspace::try_new("rollback_control_nt").unwrap();
        let queries = ParticipantPlanQueries::new(&keyspace);
        assert!(queries.create_topology_header.contains("CLUSTERING ORDER BY (topology_revision DESC)"));
        assert!(queries.create_object.contains("fragment_index ASC"));
        assert!(queries.insert_topology_header.contains("IF NOT EXISTS"));
        assert!(queries.insert_object_fragment.contains("IF NOT EXISTS"));
        for forbidden in ["DELETE ", "UPDATE ", " TTL ", "USING TIMESTAMP"] {
            assert!(!format!("{queries:?}").contains(forbidden));
        }
    }

    #[test]
    fn fragment_reconstruction_rejects_missing_extra_and_corrupt() {
        let bytes = vec![0xA5; MAX_FRAGMENT_BYTES + 7];
        let digest = [0x5A; 32];
        let header = object_header(&bytes, digest).unwrap();
        let mut fragments = bytes
            .chunks(MAX_FRAGMENT_BYTES)
            .enumerate()
            .map(|(index, payload)| {
                (index as u32, StoredObjectFragment {
                    revision: OBJECT_REVISION,
                    fragment_count: header.fragment_count,
                    object_bytes: header.object_bytes,
                    payload: payload.to_vec(),
                    fragment_digest: fragment_digest(index as u32, payload),
                    object_digest: digest,
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(reconstruct_object(fragments.clone(), &digest).unwrap(), bytes);
        assert!(reconstruct_object(vec![fragments[0].clone()], &digest).is_err());
        fragments[1].1.payload[0] ^= 1;
        assert!(reconstruct_object(fragments, &digest).is_err());
    }

    #[test]
    fn store_visibility_and_source_grant_no_barrier_or_delete() {
        let source = include_str!("rollback_participant_plan_store.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("pub async fn"));
        for forbidden in ["delete_hot_suffix(", "advance_archive_barrier(", "restore_target("] {
            assert!(!production.contains(forbidden), "forbidden {forbidden}");
        }
    }
}
