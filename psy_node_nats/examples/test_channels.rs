// src/bin/worker.rs

use async_nats::jetstream::{self, consumer::pull, stream::Stream};
use futures::StreamExt;
use tracing_subscriber::FmtSubscriber;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn, Level};

use anyhow::Result; // Use anyhow for thread-safe error handling
use serde::{Deserialize, Serialize};

// --- Data Structures (moved here to make the example self-contained) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawMessage {
    pub id: u64,
    pub data: String,
}

#[derive(Debug, Clone)]
pub struct GatheredItem {
    pub id: u64,
    pub data: String,
    pub processed_by_gatherer: bool,
    pub gathered_at: std::time::SystemTime,
}

// --- NATS Configuration ---

const NATS_URL: &str = "nats://localhost:4222";
const STREAM_NAME: &str = "DATA_PIPELINE";
// const SUBJECT_NAME: &str = "data.raw"; // Not needed in worker
const CONSUMER_NAME: &str = "worker-gatherer";

// Type alias for the signal from Processor to Gatherer
type TriggerMessage = oneshot::Sender<Vec<GatheredItem>>;

/// The Gatherer's main function.
/// It runs in a continuous loop, handling the "gathering -> handoff" cycle.
async fn gatherer(
    stream: Stream,
    mut trigger_rx: mpsc::Receiver<TriggerMessage>,
) -> Result<()> {
    // Create a durable consumer. A pull-based consumer gives us fine-grained control.
    // **FIX:** The `expires` field is the modern equivalent of `max_wait` for a pull.
    // It tells the NATS server to close the pull request after this period of inactivity.
    let consumer = stream
        .get_or_create_consumer(
            CONSUMER_NAME,
            pull::Config {
                durable_name: Some(CONSUMER_NAME.to_string()),
                // This is an important setting for this pattern. It ensures our `messages.next().await`
                // doesn't block forever if no new messages arrive.
                //expires: Some(Duration::from_secs(5)),
                ..Default::default()
            },
        )
        .await?;

    // The main cycle loop
    loop {
        let mut gathered_items: Vec<GatheredItem> = Vec::new();
        info!("GATHERER: Starting new gathering phase.");

        // **FIX:** Get a message stream. This stream will yield messages until it times out
        // based on the `expires` config above, or until it's dropped.
        let mut messages = consumer.messages().await?;

        // This is the inner loop where we actually consume from NATS.
        'gathering: loop {
            tokio::select! {
                // Biased ensures we check for a processor trigger first for better responsiveness.
                biased;

                // A trigger from the Processor was received.
                Some(responder) = trigger_rx.recv() => {
                    info!("GATHERER: Interrupted by Processor. Preparing to hand over {} items.", gathered_items.len());
                    if responder.send(gathered_items).is_err() {
                        error!("GATHERER: Failed to send data to processor. The receiver was dropped.");
                    }
                    break 'gathering; // Break inner loop to start a new cycle.
                },

                // A new message from NATS stream.
                maybe_msg = messages.next() => {
                    match maybe_msg {
                        Some(Ok(msg)) => {
                            msg.ack().await.unwrap();
                            let raw_message: RawMessage = serde_json::from_slice(&msg.payload)?;

                            // --- Light Processing Step ---
                            tokio::time::sleep(Duration::from_millis(5)).await;
                            let item = GatheredItem {
                                id: raw_message.id,
                                data: raw_message.data,
                                processed_by_gatherer: true,
                                gathered_at: std::time::SystemTime::now(),
                            };
                            info!("GATHERER: Gathered item #{}", item.id);
                            gathered_items.push(item);
                        },
                        Some(Err(e)) => {
                            error!("GATHERER: Error receiving message: {}", e);
                            // Potentially break or sleep before retrying
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        },
                        None => {
                            // The stream ended (e.g., due to the `expires` timeout).
                            // This is normal. We just loop around to get a new stream.
                            // We don't break 'gathering here, as we might be waiting for a trigger.
                            // The select loop will simply continue.
                            // To prevent a hot-loop, we can re-create the stream here.
                            messages = consumer.messages().await?;
                        }
                    }
                }
            }
        }
        info!("GATHERER: Handoff complete. Cycle restarting.");
    }
}

/// The Processor's main function.
async fn processor(trigger_tx: mpsc::Sender<TriggerMessage>) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        interval.tick().await;
        info!("PROCESSOR: Triggering gatherer to collect data...");

        let (response_tx, response_rx) = oneshot::channel();

        if trigger_tx.send(response_tx).await.is_err() {
            error!("PROCESSOR: Failed to send trigger. Gatherer has likely panicked.");
            break;
        }

        match response_rx.await {
            Ok(items) => {
                if items.is_empty() {
                    info!("PROCESSOR: Received 0 items from gatherer. Nothing to process.");
                    continue;
                }

                info!(
                    "PROCESSOR: Received {} items. Starting heavy computation...",
                    items.len()
                );
                // --- Heavy Computation Step ---
                tokio::time::sleep(Duration::from_secs(2)).await;
                info!("PROCESSOR: Heavy computation finished.");
            }
            Err(_) => {
                error!("PROCESSOR: Gatherer dropped the response channel before sending data.");
            }
        }
    }
}

// **FIX:** main now returns anyhow::Result
#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let client = async_nats::connect(NATS_URL).await?;
    let js = jetstream::new(client);



    let stream = js.get_stream(STREAM_NAME).await?;

    let (trigger_tx, trigger_rx) = mpsc::channel::<TriggerMessage>(1);

    // Spawn the tasks
    let gatherer_handle = tokio::spawn(gatherer(stream, trigger_rx));
    let processor_handle = tokio::spawn(processor(trigger_tx));

    tokio::select! {
        res = gatherer_handle => {
            error!("Gatherer task exited unexpectedly!");
            res??; // Propagate the error from the task
        },
        res = processor_handle => {
            warn!("Processor task exited.");
            res?;
        },
    }

    Ok(())
}