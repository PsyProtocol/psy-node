use scylla::client::session::Session;

pub async fn create_table_if_not_exists(session: &Session, keyspace: &str, table_name: &str, create_table_cql: &str) -> anyhow::Result<()> {
    let has_table = session
        .get_cluster_state()
        .get_keyspace(keyspace)
        .and_then(|ks| ks.tables.get(table_name))
        .is_some();

    if !has_table {
        session
            .query_unpaged(create_table_cql, &[])
            .await?;
        session.await_schema_agreement().await?;
    }
    Ok(())
}