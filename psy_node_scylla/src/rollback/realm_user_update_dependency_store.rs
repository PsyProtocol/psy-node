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
        reconstruct_component, RealmUserUpdateDependencyBundle,
        RealmUserUpdateDependencyComponent, RealmUserUpdateDependencyError,
        RealmUserUpdateDependencyFragment, RealmUserUpdateDependencyKind,
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
const PUT_TEMPLATE: &str = "INSERT INTO {table} (dependency_slot, dependency_digest, component_kind, fragment_index, fragment_count, component_bytes, component_digest, payload, payload_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
const READ_TEMPLATE: &str = "SELECT fragment_index, fragment_count, component_bytes, component_digest, payload, payload_digest FROM {table} WHERE dependency_slot = ? AND dependency_digest = ? AND component_kind = ?";

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
        for fragment in bundle.fragments() {
            let binding = put_binding(bundle, &fragment)?;
            let execution = self.session.execute_unpaged(&self.put, binding).await;
            if let Err(error) = execution {
                match self
                    .read_bundle(
                        bundle.claim_slot(),
                        *bundle.request_digest(),
                        bundle.stable_status(),
                        bundle.created_at_seconds(),
                        bundle.digest(),
                    )
                    .await
                {
                    Ok(current) if current == *bundle => return Ok(bundle.digest()),
                    _ => {
                        return Err(RealmUserUpdateDependencyStoreError::IndeterminateWrite(
                            error.to_string(),
                        ));
                    }
                }
            }
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

    pub(crate) async fn read_bundle(
        &self,
        slot: RealmUserUpdateClaimSlot,
        request_digest: [u8; 32],
        stable_status: u64,
        created_at_seconds: u32,
        dependency_digest: RealmUserUpdateDependencyDigest,
    ) -> Result<RealmUserUpdateDependencyBundle, RealmUserUpdateDependencyStoreError> {
        let mut components = Vec::with_capacity(RealmUserUpdateDependencyKind::ALL.len());
        for kind in RealmUserUpdateDependencyKind::ALL {
            components.push(
                self.read_component(slot, dependency_digest, kind).await?,
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

    async fn read_component(
        &self,
        slot: RealmUserUpdateClaimSlot,
        dependency_digest: RealmUserUpdateDependencyDigest,
        kind: RealmUserUpdateDependencyKind,
    ) -> Result<RealmUserUpdateDependencyComponent, RealmUserUpdateDependencyStoreError> {
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
        reconstruct_component(kind, fragments).map_err(Into::into)
    }
}

fn put_binding(
    bundle: &RealmUserUpdateDependencyBundle,
    fragment: &RealmUserUpdateDependencyFragment,
) -> Result<(
    Vec<u8>, Vec<u8>, i16, i32, i32, i64, Vec<u8>, Vec<u8>, Vec<u8>
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
        assert!(!queries.put().contains("TIMESTAMP"));
    }

    #[test]
    fn source_requires_quorum_write_and_exhaustive_readback() {
        let source = include_str!("realm_user_update_dependency_store.rs");
        assert!(source.contains("statement.set_consistency(Consistency::Quorum)"));
        assert!(source.contains("for kind in RealmUserUpdateDependencyKind::ALL"));
        assert!(source.contains("persist_and_readback"));
        assert!(!source.contains(&["Consistency", "::One"].concat()));
    }
}
