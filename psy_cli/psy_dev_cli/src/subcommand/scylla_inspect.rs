use clap::Parser;
use scylla::client::session::Session;
use scylla::client::session_builder::SessionBuilder;
use serde::Serialize;

#[derive(Parser, Debug)]
pub struct ScyllaInspectArgs {
    /// ScyllaDB node address (e.g. 127.0.0.1:9042)
    #[arg(long = "nodes", default_value = "127.0.0.1:9042")]
    pub nodes: String,

    /// List all keyspaces
    #[arg(long = "keyspaces", help = "List all keyspaces")]
    pub keyspaces: bool,

    /// List tables in a keyspace
    #[arg(long = "tables", help = "List tables in a keyspace")]
    pub tables: Option<String>,

    /// Run a CQL SELECT query (read-only)
    #[arg(long = "query", help = "CQL SELECT query to run")]
    pub query: Option<String>,

    /// Page size for query results
    #[arg(long = "page-size", default_value = "100")]
    pub page_size: usize,

    /// Output file (default: stdout)
    #[arg(short, long, help = "Output file path (default: stdout)")]
    pub output: Option<std::path::PathBuf>,
}

#[derive(Serialize, Debug)]
struct KeyspaceList {
    keyspaces: Vec<String>,
}

#[derive(Serialize, Debug)]
struct TableList {
    keyspace: String,
    tables: Vec<String>,
}

pub async fn run(args: ScyllaInspectArgs) -> anyhow::Result<()> {
    let session = SessionBuilder::new()
        .known_node(&args.nodes)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to ScyllaDB at {}: {}", args.nodes, e))?;

    // ── --keyspaces ──
    if args.keyspaces {
        let result = session
            .query_unpaged("SELECT keyspace_name FROM system_schema.keyspaces", &[])
            .await
            .map_err(|e| anyhow::anyhow!("Query failed: {}", e))?;
        let rows_result = result.into_rows_result().map_err(|e| anyhow::anyhow!("{}", e))?;
        let keyspaces: Vec<String> = rows_result
            .rows::<(String,)>()?
            .map(|r| r.map(|(name,)| name))
            .filter_map(Result::ok)
            .collect();
        let list = KeyspaceList { keyspaces };
        let json = serde_json::to_string_pretty(&list)?;
        write_output(&args.output, &json)?;
        return Ok(());
    }

    // ── --tables <keyspace> ──
    if let Some(keyspace) = &args.tables {
        let cql = format!(
            "SELECT table_name FROM system_schema.tables WHERE keyspace_name = '{}'",
            keyspace
        );
        let result = session
            .query_unpaged(cql, &[])
            .await
            .map_err(|e| anyhow::anyhow!("Query failed: {}", e))?;
        let rows_result = result.into_rows_result().map_err(|e| anyhow::anyhow!("{}", e))?;
        let tables: Vec<String> = rows_result
            .rows::<(String,)>()?
            .map(|r| r.map(|(name,)| name))
            .filter_map(Result::ok)
            .collect();
        let list = TableList {
            keyspace: keyspace.clone(),
            tables,
        };
        let json = serde_json::to_string_pretty(&list)?;
        write_output(&args.output, &json)?;
        return Ok(());
    }

    // ── --query <CQL> ──
    if let Some(query) = &args.query {
        let result = session
            .query_unpaged(query.clone(), &[])
            .await
            .map_err(|e| anyhow::anyhow!("Query failed: {}", e))?;
        let rows_result = result.into_rows_result().map_err(|e| anyhow::anyhow!("{}", e))?;

        // Try to deserialize rows as (String,) tuples — works for single-column queries
        let results: Vec<String> = rows_result
            .rows::<(String,)>()?
            .map(|r| r.map(|(name,)| name))
            .filter_map(Result::ok)
            .collect();

        let json = serde_json::to_string_pretty(&results)?;
        write_output(&args.output, &json)?;
        if args.output.is_none() {
            eprintln!("Returned {} rows", results.len());
        }
        return Ok(());
    }

    anyhow::bail!(
        "No action specified. Use --keyspaces, --tables <keyspace>, or --query <CQL>"
    );
}

fn write_output(output: &Option<std::path::PathBuf>, json: &str) -> anyhow::Result<()> {
    if let Some(path) = output {
        std::fs::write(path, json)?;
        eprintln!("JSON output written to: {}", path.display());
    } else {
        println!("{}", json);
    }
    Ok(())
}