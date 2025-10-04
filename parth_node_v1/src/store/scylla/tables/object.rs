use std::sync::Arc;
use parth_core::data::db::table::QDatabaseTableRoutingKey;
use scylla::{client::session::Session, statement::{prepared::PreparedStatement, Statement}};


#[derive(Clone)]
pub struct ScyllaGenericObjectSingleIdTablePreparedStatements {
    pub insert_1_statement: Statement,
    pub insert_1_prepared: Arc<PreparedStatement>,
    
    pub select_value_1_statement: Statement,
    pub select_value_1_prepared: Arc<PreparedStatement>,

    pub select_value_checkpoint_id_obj_id_1_statement: Statement,
    pub select_value_checkpoint_id_obj_id_1_prepared: Arc<PreparedStatement>,

    pub select_all_statement: Statement,
    pub select_all_prepared: Arc<PreparedStatement>,

    pub keyspace: String,
    pub table_name: String,
    pub table_key: QDatabaseTableRoutingKey,
}

impl ScyllaGenericObjectSingleIdTablePreparedStatements {
    pub async fn new_from_session(session: Arc<Session>, keyspace: &str, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<Self> {
        let insert_1_statement = Statement::new(format!("INSERT INTO {}.{} (obj_id, checkpoint_id, value) VALUES (?, ?, ?)", keyspace, table_name));
        let insert_1_prepared = session.prepare(insert_1_statement.clone()).await?;
        
        let select_value_1_statement = Statement::new(format!("SELECT value FROM {}.{} WHERE obj_id = ? AND checkpoint_id <= ? LIMIT 1", keyspace, table_name));
        let select_value_1_prepared = session.prepare(select_value_1_statement.clone()).await?;
        
        let select_value_checkpoint_id_obj_id_1_statement = Statement::new(format!("SELECT obj_id, checkpoint_id, value FROM {}.{} WHERE obj_id = ? AND checkpoint_id <= ? LIMIT 1", keyspace, table_name));
        let select_value_checkpoint_id_obj_id_1_prepared = session.prepare(select_value_checkpoint_id_obj_id_1_statement.clone()).await?;

        let select_all_statement = Statement::new(format!("SELECT obj_id, checkpoint_id, value FROM {}.{}", keyspace, table_name));
        let select_all_prepared = session.prepare(select_all_statement.clone()).await?;

        Ok(Self {
            insert_1_statement: insert_1_statement,
            insert_1_prepared: Arc::new(insert_1_prepared),
            select_value_1_statement: select_value_1_statement,
            select_value_1_prepared: Arc::new(select_value_1_prepared),
            select_value_checkpoint_id_obj_id_1_statement: select_value_checkpoint_id_obj_id_1_statement,
            select_value_checkpoint_id_obj_id_1_prepared: Arc::new(select_value_checkpoint_id_obj_id_1_prepared),
            select_all_statement: select_all_statement,
            select_all_prepared: Arc::new(select_all_prepared),
            keyspace: keyspace.to_string(),
            table_name: table_name.to_string(),
            table_key,
        })
    }
    pub async fn create_table(session: Arc<Session>, keyspace: &str, table_name: &str, _table_key: QDatabaseTableRoutingKey) -> anyhow::Result<()> {
        session
            .query_unpaged(
                format!("CREATE TABLE IF NOT EXISTS {}.{} (
                    obj_id BIGINT,
                    checkpoint_id BIGINT,
                    value BLOB,
                    PRIMARY KEY ((obj_id), checkpoint_id)
                ) WITH CLUSTERING ORDER BY (checkpoint_id DESC)", keyspace, table_name),
                &[],
            ).await?;
        session.await_schema_agreement().await?;
        Ok(())
    }
    pub async fn new_create_from_session(session: Arc<Session>, keyspace: &str, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<Self> {
        Self::create_table(session.clone(), keyspace, table_name, table_key).await?;
        Self::new_from_session(session, keyspace, table_name, table_key).await
    }
}





#[derive(Clone)]
pub struct ScyllaGenericObjectDoubleIdTablePreparedStatements {
    pub insert_1_statement: Statement,
    pub insert_1_prepared: Arc<PreparedStatement>,
    
    pub select_value_1_statement: Statement,
    pub select_value_1_prepared: Arc<PreparedStatement>,

    pub select_value_checkpoint_id_obj_ids_1_statement: Statement,
    pub select_value_checkpoint_id_obj_ids_1_prepared: Arc<PreparedStatement>,

    pub select_all_statement: Statement,
    pub select_all_prepared: Arc<PreparedStatement>,

    pub keyspace: String,
    pub table_name: String,
    pub table_key: QDatabaseTableRoutingKey,
}

impl ScyllaGenericObjectDoubleIdTablePreparedStatements {
    pub async fn new_from_session(session: Arc<Session>, keyspace: &str, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<Self> {
        let insert_1_statement = Statement::new(format!("INSERT INTO {}.{} (obj_id, secondary_id, checkpoint_id, value) VALUES (?, ?, ?, ?)", keyspace, table_name));
        let insert_1_prepared = session.prepare(insert_1_statement.clone()).await?;
        
        let select_value_1_statement = Statement::new(format!("SELECT value FROM {}.{} WHERE obj_id = ? AND secondary_id = ? AND checkpoint_id <= ? LIMIT 1", keyspace, table_name));
        let select_value_1_prepared = session.prepare(select_value_1_statement.clone()).await?;

        let select_value_checkpoint_id_obj_ids_1_statement = Statement::new(format!("SELECT obj_id, secondary_id, checkpoint_id, value FROM {}.{} WHERE obj_id = ? AND secondary_id = ? AND checkpoint_id <= ? LIMIT 1", keyspace, table_name));
        let select_value_checkpoint_id_obj_ids_1_prepared = session.prepare(select_value_checkpoint_id_obj_ids_1_statement.clone()).await?;

        let select_all_statement = Statement::new(format!("SELECT obj_id, secondary_id, checkpoint_id, value FROM {}.{}", keyspace, table_name));
        let select_all_prepared = session.prepare(select_all_statement.clone()).await?;

        Ok(Self {
            insert_1_statement: insert_1_statement,
            insert_1_prepared: Arc::new(insert_1_prepared),
            select_value_1_statement: select_value_1_statement,
            select_value_1_prepared: Arc::new(select_value_1_prepared),
            select_value_checkpoint_id_obj_ids_1_statement: select_value_checkpoint_id_obj_ids_1_statement,
            select_value_checkpoint_id_obj_ids_1_prepared: Arc::new(select_value_checkpoint_id_obj_ids_1_prepared),
            select_all_statement: select_all_statement,
            select_all_prepared: Arc::new(select_all_prepared),
            keyspace: keyspace.to_string(),
            table_name: table_name.to_string(),
            table_key,
        })
    }
    pub async fn create_table(session: Arc<Session>, keyspace: &str, table_name: &str, _table_key: QDatabaseTableRoutingKey) -> anyhow::Result<()> {
        session
            .query_unpaged(
                format!("CREATE TABLE IF NOT EXISTS {}.{} (
                    obj_id BIGINT,
                    secondary_id BIGINT,
                    checkpoint_id BIGINT,
                    value BLOB,
                    PRIMARY KEY ((obj_id, secondary_id), checkpoint_id)
                ) WITH CLUSTERING ORDER BY (checkpoint_id DESC)", keyspace, table_name),
                &[],
            ).await?;
        session.await_schema_agreement().await?;
        Ok(())
    }
    pub async fn new_create_from_session(session: Arc<Session>, keyspace: &str, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<Self> {
        Self::create_table(session.clone(), keyspace, table_name, table_key).await?;
        Self::new_from_session(session, keyspace, table_name, table_key).await
    }
}







#[derive(Clone)]
pub struct ScyllaGenericKeyIdValueTablePreparedStatements {
    pub insert_1_statement: Statement,
    pub insert_1_prepared: Arc<PreparedStatement>,
    
    pub select_value_1_statement: Statement,
    pub select_value_1_prepared: Arc<PreparedStatement>,

    pub select_value_obj_id_1_statement: Statement,
    pub select_value_obj_id_1_prepared: Arc<PreparedStatement>,

    pub select_all_statement: Statement,
    pub select_all_prepared: Arc<PreparedStatement>,

    pub keyspace: String,
    pub table_name: String,
    pub table_key: QDatabaseTableRoutingKey,
}

impl ScyllaGenericKeyIdValueTablePreparedStatements {
    pub async fn new_from_session(session: Arc<Session>, keyspace: &str, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<Self> {
        let insert_1_statement = Statement::new(format!("INSERT INTO {}.{} (obj_id, value) VALUES (?, ?)", keyspace, table_name));
        let insert_1_prepared = session.prepare(insert_1_statement.clone()).await?;
        
        let select_value_1_statement = Statement::new(format!("SELECT value FROM {}.{} WHERE obj_id = ? LIMIT 1", keyspace, table_name));
        let select_value_1_prepared = session.prepare(select_value_1_statement.clone()).await?;

        let select_value_obj_id_1_statement = Statement::new(format!("SELECT obj_id, value FROM {}.{} WHERE obj_id = ? LIMIT 1", keyspace, table_name));
        let select_value_obj_id_1_prepared = session.prepare(select_value_obj_id_1_statement.clone()).await?;

        let select_all_statement = Statement::new(format!("SELECT obj_id, value FROM {}.{}", keyspace, table_name));
        let select_all_prepared = session.prepare(select_all_statement.clone()).await?;

        Ok(Self {
            insert_1_statement: insert_1_statement,
            insert_1_prepared: Arc::new(insert_1_prepared),
            select_value_1_statement: select_value_1_statement,
            select_value_1_prepared: Arc::new(select_value_1_prepared),
            select_value_obj_id_1_statement: select_value_obj_id_1_statement,
            select_value_obj_id_1_prepared: Arc::new(select_value_obj_id_1_prepared),
            select_all_statement: select_all_statement,
            select_all_prepared: Arc::new(select_all_prepared),
            keyspace: keyspace.to_string(),
            table_name: table_name.to_string(),
            table_key,
        })
    }
    pub async fn create_table(session: Arc<Session>, keyspace: &str, table_name: &str, _table_key: QDatabaseTableRoutingKey) -> anyhow::Result<()> {
        session
            .query_unpaged(
                format!("CREATE TABLE IF NOT EXISTS {}.{} (
                    obj_id BIGINT,
                    value BLOB,
                    PRIMARY KEY ((obj_id))
                )", keyspace, table_name),
                &[],
            ).await?;
        session.await_schema_agreement().await?;
        Ok(())
    }
    pub async fn new_create_from_session(session: Arc<Session>, keyspace: &str, table_name: &str, table_key: QDatabaseTableRoutingKey) -> anyhow::Result<Self> {
        Self::create_table(session.clone(), keyspace, table_name, table_key).await?;
        Self::new_from_session(session, keyspace, table_name, table_key).await
    }
}