use clap::Parser;
use redis::AsyncCommands;
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Parser, Debug)]
pub struct RedisInspectArgs {
    /// Redis URL (e.g. redis://localhost:6379)
    #[arg(long = "url", env = "REDIS_URL", default_value = "redis://localhost:6379")]
    pub url: String,

    /// List keys matching a glob pattern (e.g. *, checkpoint-*, job-queue:*)
    #[arg(long = "keys", help = "Glob pattern for KEYS command")]
    pub keys_pattern: Option<String>,

    /// Show type + TTL for a specific key
    #[arg(long = "key-type", help = "Show TYPE + TTL for a specific key")]
    pub key_type: Option<String>,

    /// Dump value of a specific key (auto-detects type)
    #[arg(long = "dump-key", help = "Dump value of a specific key")]
    pub dump_key: Option<String>,

    /// Summarize keyspace by prefix (group keys by first ':' separator)
    #[arg(long = "keyspace", help = "Summarize keys by prefix")]
    pub keyspace: bool,

    /// Output file (default: stdout)
    #[arg(short, long, help = "Output file path (default: stdout)")]
    pub output: Option<std::path::PathBuf>,
}

#[derive(Serialize, Debug)]
struct KeyInfo {
    key: String,
    key_type: String,
    ttl: i64,
}

#[derive(Serialize, Debug)]
struct KeyspaceSummary {
    total_keys: usize,
    prefixes: Vec<(String, usize)>,
}
#[derive(Serialize, Debug)]
struct KeyDump {
    key: String,
    key_type: String,
    ttl: i64,
    value: Option<Value>,
    list_len: Option<usize>,
    hash_fields: Option<usize>,
}

pub async fn run(args: RedisInspectArgs) -> anyhow::Result<()> {
    let client = redis::Client::open(args.url.as_str())?;
    let mut conn = client.get_multiplexed_async_connection().await?;

    // ── --keys <pattern> ──
    if let Some(pattern) = &args.keys_pattern {
        let keys: Vec<String> = redis::cmd("KEYS").arg(pattern).query_async(&mut conn).await?;
        let mut key_infos = Vec::with_capacity(keys.len());
        for key in &keys {
            let key_type: String = redis::cmd("TYPE").arg(key).query_async(&mut conn).await?;
            let ttl: i64 = redis::cmd("TTL").arg(key).query_async(&mut conn).await?;
            key_infos.push(KeyInfo {
                key: key.clone(),
                key_type,
                ttl,
            });
        }
        let json = serde_json::to_string_pretty(&key_infos)?;
        write_output(&args.output, &json)?;
        if args.output.is_none() {
            eprintln!("Found {} keys matching '{}'", key_infos.len(), pattern);
        }
        return Ok(());
    }

    // ── --key-type <key> ──
    if let Some(key) = &args.key_type {
        let key_type: String = redis::cmd("TYPE").arg(key).query_async(&mut conn).await?;
        let ttl: i64 = redis::cmd("TTL").arg(key).query_async(&mut conn).await?;
        let info = KeyInfo {
            key: key.clone(),
            key_type,
            ttl,
        };
        let json = serde_json::to_string_pretty(&info)?;
        write_output(&args.output, &json)?;
        return Ok(());
    }

    // ── --dump-key <key> ──
    if let Some(key) = &args.dump_key {
        let key_type: String = redis::cmd("TYPE").arg(key).query_async(&mut conn).await?;
        let ttl: i64 = redis::cmd("TTL").arg(key).query_async(&mut conn).await?;

        let dump = match key_type.as_str() {
            "string" => {
                let val: Option<Vec<u8>> = conn.get(key).await?;
                KeyDump {
                    key: key.clone(),
                    key_type,
                    ttl,
                    value: val.map(render_bytes),
                    list_len: None,
                    hash_fields: None,
                }
            }
            "list" => {
                let vals: Vec<Vec<u8>> = conn.lrange(key, 0, 99).await?;
                let len = vals.len();
                KeyDump {
                    key: key.clone(),
                    key_type,
                    ttl,
                    value: Some(Value::Array(vals.into_iter().map(render_bytes).collect())),
                    list_len: Some(len),
                    hash_fields: None,
                }
            }
            "hash" => {
                let map: std::collections::HashMap<Vec<u8>, Vec<u8>> = conn.hgetall(key).await?;
                let fields = map.len();
                let rendered: Vec<Value> = map
                    .into_iter()
                    .map(|(k, v)| {
                        json!({
                            "field": render_bytes(k),
                            "value": render_bytes(v),
                        })
                    })
                    .collect();
                KeyDump {
                    key: key.clone(),
                    key_type,
                    ttl,
                    value: Some(Value::Array(rendered)),
                    list_len: None,
                    hash_fields: Some(fields),
                }
            }
            "set" => {
                let members: Vec<Vec<u8>> = conn.smembers(key).await?;
                let len = members.len();
                KeyDump {
                    key: key.clone(),
                    key_type,
                    ttl,
                    value: Some(Value::Array(members.into_iter().map(render_bytes).collect())),
                    list_len: Some(len),
                    hash_fields: None,
                }
            }
            "zset" => {
                let members: Vec<(Vec<u8>, f64)> = conn.zrange_withscores(key, 0, 99).await?;
                let len = members.len();
                let rendered: Vec<Value> = members
                    .into_iter()
                    .map(|(member, score)| {
                        json!({
                            "member": render_bytes(member),
                            "score": score,
                        })
                    })
                    .collect();
                KeyDump {
                    key: key.clone(),
                    key_type,
                    ttl,
                    value: Some(Value::Array(rendered)),
                    list_len: Some(len),
                    hash_fields: None,
                }
            }
            "none" => KeyDump {
                key: key.clone(),
                key_type: "none".to_string(),
                ttl: -2,
                value: None,
                list_len: None,
                hash_fields: None,
            },
            other => KeyDump {
                key: key.clone(),
                key_type: other.to_string(),
                ttl,
                value: Some(json!({
                    "warning": format!("type '{}' not supported for dump", other),
                })),
                list_len: None,
                hash_fields: None,
            },
        };

        let json = serde_json::to_string_pretty(&dump)?;
        write_output(&args.output, &json)?;
        return Ok(());
    }

    // ── --keyspace ──
    if args.keyspace {
        let keys: Vec<String> = redis::cmd("KEYS").arg("*").query_async(&mut conn).await?;
        let mut prefixes: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for key in &keys {
            let prefix = key.split(':').next().unwrap_or(key).to_string();
            *prefixes.entry(prefix).or_insert(0) += 1;
        }
        let mut sorted: Vec<(String, usize)> = prefixes.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        let summary = KeyspaceSummary {
            total_keys: keys.len(),
            prefixes: sorted,
        };
        let json = serde_json::to_string_pretty(&summary)?;
        write_output(&args.output, &json)?;
        if args.output.is_none() {
            eprintln!("Total keys: {}", summary.total_keys);
        }
        return Ok(());
    }

    // No flags — default to keyspace summary
    anyhow::bail!(
        "No action specified. Use --keys <pattern>, --key-type <key>, --dump-key <key>, or --keyspace"
    );
}

fn render_bytes(bytes: Vec<u8>) -> Value {
    let text = String::from_utf8(bytes.clone()).ok();
    json!({
        "hex": hex::encode(&bytes),
        "utf8": text,
    })
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