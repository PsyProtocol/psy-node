//! Immutable Scylla fragments for one exact Realm user-update dependency set.
//!
//! The claim row is the small LWT authority. This standard/tablet table holds
//! deterministic large bytes; every write is followed by a QUORUM exhaustive
//! readback before the claim may advance to `DependenciesReady`.

use std::{error::Error, fmt, sync::Arc};

use psy_node_core::queue::{
    realm_user_update_claim::{
        RealmUserUpdateClaimSlot, RealmUserUpdateDependencyDigest,
    },
    realm_user_update_dependency::{
        plan_realm_user_update_dependency_recovery, reconstruct_component,
        RealmUserUpdateDependencyBundle, RealmUserUpdateDependencyError,
        RealmUserUpdateDependencyFragment,
        RealmUserUpdateDependencyKind, RealmUserUpdateDependencyRecoveryPlan,
        RealmUserUpdateDependencyWriteTimestampUs,
    },
};
use scylla::{
    client::session::Session,
    statement::{prepared::PreparedStatement, Consistency},
};

use super::PendingQueueArtifactDataKeyspace;

pub const REALM_USER_UPDATE_DEPENDENCY_FRAGMENT_TABLE: &str =
    "branch_exact_realm_user_update_dependency_fragment_v1";

const CREATE_TEMPLATE: &str = "CREATE TABLE IF NOT EXISTS {table} (dependency_slot blob, dependency_digest blob, component_kind smallint, fragment_index int, fragment_count int, component_bytes bigint, component_digest blob, payload blob, payload_digest blob, PRIMARY KEY ((dependency_slot, dependency_digest, component_kind), fragment_index)) WITH CLUSTERING ORDER BY (fragment_index ASC)";
const PUT_TEMPLATE: &str = "INSERT INTO {table} (dependency_slot, dependency_digest, component_kind, fragment_index, fragment_count, component_bytes, component_digest, payload, payload_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) USING TIMESTAMP ?";
const READ_TEMPLATE: &str = "SELECT fragment_index, fragment_count, component_bytes, component_digest, payload, payload_digest, writetime(payload) AS payload_write_timestamp_us FROM {table} WHERE dependency_slot = ? AND dependency_digest = ? AND component_kind = ?";

const PUT_BIND_SHAPE: &[&str] = &[
    "dependency_slot:BLOB",
    "dependency_digest:BLOB",
    "component_kind:SMALLINT",
    "fragment_index:INT",
    "fragment_count:INT",
    "component_bytes:BIGINT",
    "component_digest:BLOB",
    "payload:BLOB",
    "payload_digest:BLOB",
    "write_timestamp_us:BIGINT",
];
const READ_BIND_SHAPE: &[&str] = &[
    "dependency_slot:BLOB",
    "dependency_digest:BLOB",
    "component_kind:SMALLINT",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateDependencyQueries {
    create: String,
    put: String,
    read: String,
}

impl RealmUserUpdateDependencyQueries {
    pub fn new(keyspace: &PendingQueueArtifactDataKeyspace) -> Self {
        let table = format!(
            "{}.{}",
            keyspace.as_str(),
            REALM_USER_UPDATE_DEPENDENCY_FRAGMENT_TABLE
        );
        Self {
            create: CREATE_TEMPLATE.replace("{table}", &table),
            put: PUT_TEMPLATE.replace("{table}", &table),
            read: READ_TEMPLATE.replace("{table}", &table),
        }
    }

    pub fn create(&self) -> &str { &self.create }
    pub fn put(&self) -> &str { &self.put }
    pub fn read(&self) -> &str { &self.read }
    pub const fn put_bind_shape(&self) -> &'static [&'static str] { PUT_BIND_SHAPE }
    pub const fn read_bind_shape(&self) -> &'static [&'static str] { READ_BIND_SHAPE }
}

#[derive(scylla::DeserializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct DependencyFragmentRow {
    fragment_index: i32,
    fragment_count: i32,
    component_bytes: i64,
    component_digest: Vec<u8>,
    payload: Vec<u8>,
    payload_digest: Vec<u8>,
    payload_write_timestamp_us: i64,
}

pub(crate) struct ScyllaRealmUserUpdateDependencyStore {
    session: Arc<Session>,
    queries: RealmUserUpdateDependencyQueries,
    put: PreparedStatement,
    read: PreparedStatement,
}

impl ScyllaRealmUserUpdateDependencyStore {
    pub(crate) async fn create_schema(
        session: &Session,
        keyspace: &PendingQueueArtifactDataKeyspace,
    ) -> Result<(), RealmUserUpdateDependencyStoreError> {
        let queries = RealmUserUpdateDependencyQueries::new(keyspace);
        session
            .query_unpaged(queries.create(), &[])
            .await
            .map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub(crate) async fn prepare(
        session: Arc<Session>,
        keyspace: PendingQueueArtifactDataKeyspace,
    ) -> Result<Self, RealmUserUpdateDependencyStoreError> {
        let queries = RealmUserUpdateDependencyQueries::new(&keyspace);
        let put = prepare(&session, queries.put()).await?;
        let read = prepare(&session, queries.read()).await?;
        Ok(Self { session, queries, put, read })
    }

    pub(crate) const fn queries(&self) -> &RealmUserUpdateDependencyQueries {
        &self.queries
    }

    pub(crate) async fn persist_and_readback(
        &self,
        bundle: &RealmUserUpdateDependencyBundle,
    ) -> Result<RealmUserUpdateDependencyDigest, RealmUserUpdateDependencyStoreError> {
        let recovery = self.inspect_recovery(bundle).await?;
        self.apply_recovery_plan(bundle, &recovery).await
    }

    async fn apply_recovery_plan(
        &self,
        bundle: &RealmUserUpdateDependencyBundle,
        recovery: &RealmUserUpdateDependencyRecoveryPlan,
    ) -> Result<RealmUserUpdateDependencyDigest, RealmUserUpdateDependencyStoreError> {
        for fragment in recovery.missing_fragments() {
            let binding = put_binding(bundle, fragment)?;
            let execution = self.session.execute_unpaged(&self.put, binding).await;
            if let Err(error) = execution {
                match self.inspect_recovery(bundle).await {
                    Ok(current) if current.is_complete() => return Ok(bundle.digest()),
                    Err(error @ RealmUserUpdateDependencyStoreError::Dependency(_)) => {
                        return Err(error);
                    }
                    _ => {
                        return Err(RealmUserUpdateDependencyStoreError::IndeterminateWrite(
                            error.to_string(),
                        ));
                    }
                }
            }
        }
        let completed = self.inspect_recovery(bundle).await?;
        if !completed.is_complete() {
            return Err(RealmUserUpdateDependencyStoreError::ReadbackMismatch);
        }
        let current = self
            .read_bundle(
                bundle.claim_slot(),
                *bundle.request_digest(),
                bundle.stable_status(),
                bundle.created_at_seconds(),
                bundle.digest(),
            )
            .await?;
        if current != *bundle {
            return Err(RealmUserUpdateDependencyStoreError::ReadbackMismatch);
        }
        Ok(bundle.digest())
    }

    /// Test-only TOCTOU seam. The caller first obtains a typed plan, injects a
    /// competing row, and then applies that stale plan through the exact same
    /// production PUT/post-inspection/readback implementation.
    #[cfg(test)]
    pub(crate) async fn apply_stale_recovery_plan_fixture(
        &self,
        bundle: &RealmUserUpdateDependencyBundle,
        recovery: &RealmUserUpdateDependencyRecoveryPlan,
    ) -> Result<RealmUserUpdateDependencyDigest, RealmUserUpdateDependencyStoreError> {
        self.apply_recovery_plan(bundle, recovery).await
    }

    /// Test-only typed crash seam. It writes only the requested exact
    /// coordinates through the same prepared statement and binding path as
    /// production, then returns the durable missing-only plan without filling
    /// the remaining fragments.
    #[cfg(test)]
    pub(crate) async fn persist_exact_subset_through_crash_fixture(
        &self,
        bundle: &RealmUserUpdateDependencyBundle,
        coordinates: &[(RealmUserUpdateDependencyKind, u32)],
    ) -> Result<RealmUserUpdateDependencyRecoveryPlan, RealmUserUpdateDependencyStoreError> {
        let before = self.inspect_recovery(bundle).await?;
        let missing = before
            .missing_fragments()
            .iter()
            .map(|fragment| (fragment.kind(), fragment.index()))
            .collect::<std::collections::BTreeSet<_>>();
        let selected = coordinates
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        if selected.len() != coordinates.len()
            || !selected.iter().all(|coordinate| missing.contains(coordinate))
        {
            return Err(RealmUserUpdateDependencyStoreError::InvalidRecoverySubset);
        }
        let fragments = bundle.fragments();
        for coordinate in selected {
            let fragment = fragments
                .iter()
                .find(|fragment| (fragment.kind(), fragment.index()) == coordinate)
                .ok_or(RealmUserUpdateDependencyStoreError::InvalidRecoverySubset)?;
            let binding = put_binding(bundle, fragment)?;
            self.session
                .execute_unpaged(&self.put, binding)
                .await
                .map_err(|error| {
                    RealmUserUpdateDependencyStoreError::IndeterminateWrite(
                        error.to_string(),
                    )
                })?;
        }
        self.inspect_recovery(bundle).await
    }

    /// Read all five selected component partitions and classify them against
    /// a complete typed candidate. It never mutates rows or turns malformed,
    /// duplicate, extra, or conflicting data into a repairable gap.
    pub(crate) async fn inspect_recovery(
        &self,
        expected: &RealmUserUpdateDependencyBundle,
    ) -> Result<RealmUserUpdateDependencyRecoveryPlan, RealmUserUpdateDependencyStoreError> {
        let mut observed = Vec::new();
        for kind in RealmUserUpdateDependencyKind::ALL {
            observed.extend(
                self.read_fragments(
                    expected.claim_slot(),
                    expected.digest(),
                    kind,
                    Some(expected.write_timestamp_us()),
                )
                .await?,
            );
        }
        plan_realm_user_update_dependency_recovery(expected, observed)
            .map_err(Into::into)
    }

    pub(crate) async fn read_bundle(
        &self,
        slot: RealmUserUpdateClaimSlot,
        request_digest: [u8; 32],
        stable_status: u64,
        created_at_seconds: u32,
        dependency_digest: RealmUserUpdateDependencyDigest,
    ) -> Result<RealmUserUpdateDependencyBundle, RealmUserUpdateDependencyStoreError> {
        self.read_bundle_with_timestamp(
            slot,
            request_digest,
            stable_status,
            created_at_seconds,
            dependency_digest,
            None,
        )
        .await
    }

    /// Planned recovery is still a write-authorizing boundary. Every existing
    /// fragment must carry the exact timestamp derived from the durable claim
    /// and dependency identity. Ready/Published readers remain content-only
    /// because they never write or advance readiness.
    pub(crate) async fn read_planned_bundle(
        &self,
        slot: RealmUserUpdateClaimSlot,
        request_digest: [u8; 32],
        stable_status: u64,
        created_at_seconds: u32,
        dependency_digest: RealmUserUpdateDependencyDigest,
    ) -> Result<RealmUserUpdateDependencyBundle, RealmUserUpdateDependencyStoreError> {
        self.read_bundle_with_timestamp(
            slot,
            request_digest,
            stable_status,
            created_at_seconds,
            dependency_digest,
            Some(RealmUserUpdateDependencyWriteTimestampUs::derive(
                slot,
                dependency_digest,
                created_at_seconds,
            )),
        )
        .await
    }

    async fn read_bundle_with_timestamp(
        &self,
        slot: RealmUserUpdateClaimSlot,
        request_digest: [u8; 32],
        stable_status: u64,
        created_at_seconds: u32,
        dependency_digest: RealmUserUpdateDependencyDigest,
        expected_write_timestamp_us: Option<RealmUserUpdateDependencyWriteTimestampUs>,
    ) -> Result<RealmUserUpdateDependencyBundle, RealmUserUpdateDependencyStoreError> {
        let mut components = Vec::with_capacity(RealmUserUpdateDependencyKind::ALL.len());
        for kind in RealmUserUpdateDependencyKind::ALL {
            components.push(
                reconstruct_component(
                    kind,
                    self.read_fragments(
                        slot,
                        dependency_digest,
                        kind,
                        expected_write_timestamp_us,
                    )
                    .await?,
                )
                .map_err(RealmUserUpdateDependencyStoreError::from)?,
            );
        }
        RealmUserUpdateDependencyBundle::reconstruct(
            slot,
            request_digest,
            stable_status,
            created_at_seconds,
            components,
            dependency_digest,
        )
        .map_err(Into::into)
    }

    async fn read_fragments(
        &self,
        slot: RealmUserUpdateClaimSlot,
        dependency_digest: RealmUserUpdateDependencyDigest,
        kind: RealmUserUpdateDependencyKind,
        expected_write_timestamp_us: Option<RealmUserUpdateDependencyWriteTimestampUs>,
    ) -> Result<Vec<RealmUserUpdateDependencyFragment>, RealmUserUpdateDependencyStoreError> {
        let result = self
            .session
            .execute_unpaged(
                &self.read,
                (
                    slot.as_bytes().as_slice(),
                    dependency_digest.as_bytes().as_slice(),
                    kind.as_i16(),
                ),
            )
            .await
            .map_err(cql)?;
        let rows = result.into_rows_result().map_err(cql)?;
        let mut fragments = Vec::new();
        for row in rows.rows::<DependencyFragmentRow>().map_err(cql)? {
            let row = row.map_err(cql)?;
            if let Some(expected) = expected_write_timestamp_us {
                if row.payload_write_timestamp_us != expected.as_i64() {
                    return Err(RealmUserUpdateDependencyStoreError::TimestampMismatch {
                        expected: expected.as_i64(),
                        actual: row.payload_write_timestamp_us,
                    });
                }
            }
            fragments.push(RealmUserUpdateDependencyFragment::decode(
                kind,
                row.fragment_index,
                row.fragment_count,
                row.component_bytes,
                row.component_digest,
                row.payload,
                row.payload_digest,
            )?);
        }
        Ok(fragments)
    }
}

fn put_binding(
    bundle: &RealmUserUpdateDependencyBundle,
    fragment: &RealmUserUpdateDependencyFragment,
) -> Result<(
    Vec<u8>, Vec<u8>, i16, i32, i32, i64, Vec<u8>, Vec<u8>, Vec<u8>, i64
), RealmUserUpdateDependencyStoreError> {
    Ok((
        bundle.claim_slot().as_bytes().to_vec(),
        bundle.digest().as_bytes().to_vec(),
        fragment.kind().as_i16(),
        i32::try_from(fragment.index()).map_err(|_| RealmUserUpdateDependencyStoreError::CoordinateOutOfRange)?,
        i32::try_from(fragment.count()).map_err(|_| RealmUserUpdateDependencyStoreError::CoordinateOutOfRange)?,
        i64::try_from(fragment.component_bytes()).map_err(|_| RealmUserUpdateDependencyStoreError::CoordinateOutOfRange)?,
        fragment.component_digest().as_bytes().to_vec(),
        fragment.payload().to_vec(),
        fragment.payload_digest().to_vec(),
        bundle.write_timestamp_us().as_i64(),
    ))
}

async fn prepare(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, RealmUserUpdateDependencyStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn cql(error: impl fmt::Display) -> RealmUserUpdateDependencyStoreError {
    RealmUserUpdateDependencyStoreError::Cql(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmUserUpdateDependencyStoreError {
    Dependency(RealmUserUpdateDependencyError),
    CoordinateOutOfRange,
    ReadbackMismatch,
    TimestampMismatch { expected: i64, actual: i64 },
    InvalidRecoverySubset,
    IndeterminateWrite(String),
    Cql(String),
}

impl From<RealmUserUpdateDependencyError> for RealmUserUpdateDependencyStoreError {
    fn from(error: RealmUserUpdateDependencyError) -> Self { Self::Dependency(error) }
}

impl fmt::Display for RealmUserUpdateDependencyStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmUserUpdateDependencyStoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_and_bind_order_are_exact() {
        let keyspace = PendingQueueArtifactDataKeyspace::try_new("psy_dependency_data").unwrap();
        let queries = RealmUserUpdateDependencyQueries::new(&keyspace);
        assert!(queries.create().contains("PRIMARY KEY ((dependency_slot, dependency_digest, component_kind), fragment_index)"));
        assert!(queries.create().contains("CLUSTERING ORDER BY (fragment_index ASC)"));
        assert_eq!(queries.put_bind_shape(), PUT_BIND_SHAPE);
        assert_eq!(queries.read_bind_shape(), READ_BIND_SHAPE);
        assert!(!queries.put().contains("IF NOT EXISTS"));
        assert!(!queries.put().contains("TTL"));
        assert!(queries.put().contains("USING TIMESTAMP ?"));
        assert!(queries
            .read()
            .contains("writetime(payload) AS payload_write_timestamp_us"));
    }

    #[test]
    fn source_requires_quorum_write_and_exhaustive_readback() {
        let source = include_str!("realm_user_update_dependency_store.rs");
        assert!(source.contains("statement.set_consistency(Consistency::Quorum)"));
        assert!(source.contains("for kind in RealmUserUpdateDependencyKind::ALL"));
        assert!(source.contains("persist_and_readback"));
        assert!(!source.contains(&["Consistency", "::One"].concat()));

        let persist = source.find("pub(crate) async fn persist_and_readback").unwrap();
        let inspect = source[persist..]
            .find("pub(crate) async fn inspect_recovery")
            .map(|offset| persist + offset)
            .unwrap();
        let body = &source[persist..inspect];
        assert!(body.contains("self.inspect_recovery(bundle).await?"));
        assert!(body.contains("recovery.missing_fragments()"));
        assert!(body.contains("RealmUserUpdateDependencyStoreError::Dependency(_)"));
        assert!(body.contains("put_binding(bundle, fragment)"));
        assert!(body.contains("let completed = self.inspect_recovery(bundle).await?"));
        assert!(!body.contains("for fragment in bundle.fragments()"));

        let planned = source
            .find("pub(crate) async fn read_planned_bundle")
            .unwrap();
        let planned_body = &source[planned..source[planned..]
            .find("    async fn read_bundle_with_timestamp")
            .map(|offset| planned + offset)
            .unwrap()];
        assert!(planned_body.contains("RealmUserUpdateDependencyWriteTimestampUs::derive"));
        assert!(planned_body.contains("Some("));
    }
}
