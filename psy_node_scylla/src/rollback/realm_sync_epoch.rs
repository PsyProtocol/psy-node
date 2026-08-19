//! Scylla storage for the epoch a Realm synced under.
//!
//! See `psy_node_core::store::realm_sync_epoch` for why it exists.

use std::sync::Arc;

use psy_node_core::store::realm_sync_epoch::RealmSyncEpochStore;
use scylla::client::session::Session;
use scylla::statement::prepared::PreparedStatement;

pub const REALM_SYNC_EPOCH_TABLE: &str = "realm_sync_epoch";

pub struct ScyllaRealmSyncEpochStore {
    session: Arc<Session>,
    network_chain_id: i64,
    read: PreparedStatement,
    write: PreparedStatement,
}

impl ScyllaRealmSyncEpochStore {
    pub async fn create_table(session: &Session, no_tablet_keyspace: &str) -> anyhow::Result<()> {
        session
            .query_unpaged(
                format!(
                    "CREATE TABLE IF NOT EXISTS {no_tablet_keyspace}.{REALM_SYNC_EPOCH_TABLE} (
                        network_chain_id BIGINT,
                        chain_epoch BIGINT,
                        PRIMARY KEY ((network_chain_id))
                    )"
                ),
                &[],
            )
            .await?;
        session.await_schema_agreement().await?;
        Ok(())
    }

    pub async fn prepare(
        session: Arc<Session>,
        no_tablet_keyspace: &str,
        network_chain_id: i64,
    ) -> anyhow::Result<Self> {
        let read = session
            .prepare(format!(
                "SELECT chain_epoch FROM {no_tablet_keyspace}.{REALM_SYNC_EPOCH_TABLE} \
                 WHERE network_chain_id = ?"
            ))
            .await?;
        let write = session
            .prepare(format!(
                "INSERT INTO {no_tablet_keyspace}.{REALM_SYNC_EPOCH_TABLE} \
                 (network_chain_id, chain_epoch) VALUES (?, ?)"
            ))
            .await?;
        Ok(Self {
            session,
            network_chain_id,
            read,
            write,
        })
    }
}

#[async_trait::async_trait]
impl RealmSyncEpochStore for ScyllaRealmSyncEpochStore {
    async fn read_synced_epoch(&self) -> anyhow::Result<Option<u64>> {
        let rows = self
            .session
            .execute_unpaged(
                &self.read,
                (self.network_chain_id,),
            )
            .await?
            .into_rows_result()?
            .rows::<(i64,)>()?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows.first().map(|(epoch,)| *epoch as u64))
    }

    async fn write_synced_epoch(&self, chain_epoch: u64) -> anyhow::Result<()> {
        self.session
            .execute_unpaged(
                &self.write,
                (self.network_chain_id, chain_epoch as i64),
            )
            .await?;
        Ok(())
    }
}
