use clap::Parser;
use futures::StreamExt;
use serde::Serialize;

#[derive(Parser, Debug)]
pub struct NatsInspectArgs {
    /// NATS server URL (e.g. nats://localhost:4222)
    #[arg(long = "server", env = "NATS_URL", default_value = "nats://localhost:4222")]
    pub server: String,

    /// List all JetStream streams
    #[arg(long = "list-streams", help = "List all JetStream streams")]
    pub list_streams: bool,

    /// Show info for a specific stream
    #[arg(long = "stream", help = "Show stream info")]
    pub stream: Option<String>,

    /// Subscribe to a subject and collect N messages
    #[arg(long = "sub", help = "Subscribe to subject and collect messages")]
    pub sub: Option<String>,

    /// Number of messages to collect (with --sub)
    #[arg(long = "count", default_value = "10")]
    pub count: usize,

    /// Timeout in seconds for message collection
    #[arg(long = "timeout", default_value = "5")]
    pub timeout: u64,

    /// Output file (default: stdout)
    #[arg(short, long, help = "Output file path (default: stdout)")]
    pub output: Option<std::path::PathBuf>,
}

#[derive(Serialize, Debug)]
struct StreamInfoOut {
    name: String,
    subjects: Vec<String>,
    messages: u64,
    bytes: u64,
    consumer_count: usize,
}

#[derive(Serialize, Debug)]
struct NatsMessage {
    subject: String,
    timestamp: String,
    payload_hex: String,
    payload_text: Option<String>,
}

pub async fn run(args: NatsInspectArgs) -> anyhow::Result<()> {
    let client = async_nats::connect(&args.server).await?;
    let context = async_nats::jetstream::new(client.clone());

    // ── --list-streams ──
    if args.list_streams {
        let mut stream_names = context.stream_names();
        let mut stream_infos = Vec::new();
        while let Some(name_result) = stream_names.next().await {
            let name = name_result.map_err(|e| anyhow::anyhow!("Stream name error: {}", e))?;
            // Use get_stream to fetch the stream, then info() to get the Info
            match context.get_stream(&name).await {
                Ok(mut stream) => {
                    match stream.info().await {
                        Ok(info) => {
                            stream_infos.push(StreamInfoOut {
                                name: info.config.name.clone(),
                                subjects: info.config.subjects.clone(),
                                messages: info.state.messages,
                                bytes: info.state.bytes,
                                consumer_count: info.state.consumer_count,
                            });
                        }
                        Err(e) => {
                            eprintln!("Warning: failed to get info for stream '{}': {}", name, e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Warning: failed to get stream '{}': {}", name, e);
                }
            }
        }

        let json = serde_json::to_string_pretty(&stream_infos)?;
        write_output(&args.output, &json)?;
        return Ok(());
    }

    // ── --stream <name> ──
    if let Some(stream_name) = &args.stream {
        let mut stream = context
            .get_stream(stream_name)
            .await
            .map_err(|e| anyhow::anyhow!("Stream '{}' not found: {}", stream_name, e))?;
        let info = stream
            .info()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get stream info: {}", e))?;

        let si = StreamInfoOut {
            name: info.config.name.clone(),
            subjects: info.config.subjects.clone(),
            messages: info.state.messages,
            bytes: info.state.bytes,
            consumer_count: info.state.consumer_count,
        };

        let json = serde_json::to_string_pretty(&si)?;
        write_output(&args.output, &json)?;
        return Ok(());
    }

    // ── --sub <subject> ──
    if let Some(subject) = &args.sub {
        let mut sub = client
            .subscribe(subject.clone())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to subscribe to '{}': {}", subject, e))?;

        let mut messages = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(args.timeout),
            async {
                while messages.len() < args.count {
                    if let Some(msg) = sub.next().await {
                        let payload = msg.payload.to_vec();
                        let payload_text = String::from_utf8(payload.clone()).ok();
                        messages.push(NatsMessage {
                            subject: msg.subject.to_string(),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                            payload_hex: hex::encode(&payload),
                            payload_text,
                        });
                    } else {
                        break;
                    }
                }
            },
        )
        .await;

        let json = serde_json::to_string_pretty(&messages)?;
        write_output(&args.output, &json)?;
        if args.output.is_none() {
            eprintln!("Collected {} messages on subject '{}'", messages.len(), subject);
        }
        return Ok(());
    }

    anyhow::bail!(
        "No action specified. Use --list-streams, --stream <name>, or --sub <subject> --count <n>"
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