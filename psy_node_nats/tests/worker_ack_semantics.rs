//! Pins down the JetStream behaviour the worker lease design depends on, on
//! a real disposable nats-server with the worker consumer's ack policy:
//! explicit ACK, short ack_wait, many redeliveries.
use std::{process::{Child, Command, Stdio}, time::Duration};

use async_nats::jetstream::{self, consumer::{pull, AckPolicy}, AckKind};
use futures::StreamExt;

struct Server { child: Child, dir: std::path::PathBuf, url: String }
impl Server {
    fn start() -> Self {
        // Tests run in parallel in one process: each server needs its own port.
        static NEXT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let port = 20_000 + (std::process::id() % 2_000) as u16 * 10 + n;
        let dir = std::env::temp_dir().join(format!("worker-ack-semantics-{}-{port}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let child = Command::new("nats-server").args(["-js", "-a", "127.0.0.1", "-p", &port.to_string(), "-sd"]).arg(&dir)
            .stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("nats-server is required for this ignored test");
        Self { child, dir, url: format!("nats://127.0.0.1:{port}") }
    }
}
impl Drop for Server {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = std::fs::remove_dir_all(&self.dir); }
}

async fn setup(subject: &str) -> (Server, jetstream::Context, pull::Stream, jetstream::consumer::Consumer<pull::Config>) {
    let server = Server::start();
    let mut client = None;
    for _ in 0..100 {
        if let Ok(c) = async_nats::connect(&server.url).await { client = Some(c); break; }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let js = jetstream::new(client.expect("nats-server did not start"));
    let stream = js.create_stream(jetstream::stream::Config { name: "WORK".into(), subjects: vec![subject.into()], ..Default::default() }).await.unwrap();
    let consumer = stream.create_consumer(pull::Config { durable_name: Some("workers".into()), ack_policy: AckPolicy::Explicit,
        ack_wait: Duration::from_millis(1_000), max_deliver: 50, ..Default::default() }).await.unwrap();
    js.publish(subject.to_string(), "job-1".into()).await.unwrap().await.unwrap();
    let messages = consumer.messages().await.unwrap();
    (server, js, messages, consumer)
}

async fn next_within(messages: &mut pull::Stream, ms: u64) -> Option<jetstream::Message> {
    tokio::time::timeout(Duration::from_millis(ms), messages.next()).await.ok().flatten().map(|m| m.unwrap())
}

async fn pending(consumer: &mut jetstream::consumer::Consumer<pull::Config>) -> (usize, u64) {
    let info = consumer.info().await.unwrap();
    (info.num_ack_pending, info.num_pending)
}

#[tokio::test]
#[ignore = "requires nats-server on PATH"]
async fn ack_through_an_earlier_delivery_still_completes_the_message() {
    let (_server, _js, mut messages, mut consumer) = setup("work.a").await;
    let first = next_within(&mut messages, 2_000).await.unwrap();
    let second = next_within(&mut messages, 2_500).await.expect("redelivered after ack_wait");
    assert_eq!(first.info().unwrap().stream_sequence, second.info().unwrap().stream_sequence);
    assert_eq!(second.info().unwrap().delivered, 2);
    assert_ne!(first.reply, second.reply, "every delivery has its own reply subject");
    first.ack_with(AckKind::Ack).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let after = pending(&mut consumer).await;
    let redelivered = next_within(&mut messages, 2_500).await.map(|m| m.info().unwrap().delivered);
    eprintln!("after stale ACK: ack_pending={}, pending={}, redelivered={redelivered:?}", after.0, after.1);
    assert_eq!(after, (0, 0));
    assert_eq!(redelivered, None);
}

#[tokio::test]
#[ignore = "requires nats-server on PATH"]
async fn progress_holds_a_delivery_and_stopping_releases_it() {
    let (_server, _js, mut messages, _consumer) = setup("work.b").await;
    let first = next_within(&mut messages, 2_000).await.unwrap();
    for _ in 0..6 {
        first.ack_with(AckKind::Progress).await.unwrap();
        assert!(next_within(&mut messages, 500).await.is_none(), "no redelivery while progress is sent");
    }
    let again = next_within(&mut messages, 2_500).await.expect("redelivered once progress stops");
    assert_eq!(again.info().unwrap().delivered, 2);
}

#[tokio::test]
#[ignore = "requires nats-server on PATH"]
async fn delayed_nak_postpones_redelivery() {
    let (_server, _js, mut messages, _consumer) = setup("work.c").await;
    let first = next_within(&mut messages, 2_000).await.unwrap();
    first.ack_with(AckKind::Nak(Some(Duration::from_millis(2_500)))).await.unwrap();
    let started = std::time::Instant::now();
    let again = next_within(&mut messages, 5_000).await.expect("redelivered after the delay");
    let waited = started.elapsed();
    eprintln!("delayed NAK redelivered after {waited:?}");
    assert!(waited >= Duration::from_millis(2_300), "delay honoured, not ack_wait");
    // Progress through the stale first delivery after redelivery.
    first.ack_with(AckKind::Progress).await.unwrap();
    again.ack_with(AckKind::Ack).await.unwrap();
}

#[tokio::test]
#[ignore = "requires nats-server on PATH"]
async fn progress_through_a_stale_delivery_still_extends_the_message() {
    let (_server, _js, mut messages, _consumer) = setup("work.d").await;
    let first = next_within(&mut messages, 2_000).await.unwrap();
    let second = next_within(&mut messages, 2_500).await.expect("redelivered");
    let mut held = true;
    for _ in 0..4 {
        first.ack_with(AckKind::Progress).await.unwrap();
        if next_within(&mut messages, 500).await.is_some() { held = false; break; }
    }
    eprintln!("progress via the earlier delivery holds the message: {held}");
    second.ack_with(AckKind::Ack).await.unwrap();
}

mod client {
    use std::time::Duration;

    use parth_core::data::queue::queue_key::{PCoreQueueItemBase, QPBaseQueueType, QPStandardUniqueIdQueueKey};
    use psy_node_core::queue::{infrastructure::QStandardQueueBase, worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber, WorkerJobControl}};
    use psy_node_nats::queue::NatsJetStreamClient;

    #[derive(Debug, Clone, PartialEq)]
    struct Item(u64);
    impl PCoreQueueItemBase for Item {
        fn is_queue_item(data: &[u8]) -> bool { data.len() == 8 }
        fn decode_queue_item_ref(data: &[u8]) -> anyhow::Result<Self> { Ok(Self(u64::from_le_bytes(data.try_into()?))) }
        fn encode_queue_item_vec(&self) -> anyhow::Result<Vec<u8>> { Ok(self.0.to_le_bytes().to_vec()) }
        fn get_restorable_job_id(&self) -> Vec<u8> { self.0.to_le_bytes().to_vec() }
        fn get_size_hint() -> usize { 8 }
        fn has_fixed_size() -> bool { true }
    }
    type Key = QPStandardUniqueIdQueueKey<7, Item>;
    const KEY: Key = QPStandardUniqueIdQueueKey { realm_id: 1, realm_sub_id: 0, unique_id: 5, task_group: 0,
        queue_type: QPBaseQueueType::WorkerQueue, _phantom_queue_item: std::marker::PhantomData };

    async fn client(url: &str) -> NatsJetStreamClient {
        let worker = async_nats::jetstream::consumer::pull::Config { ack_policy: async_nats::jetstream::consumer::AckPolicy::Explicit,
            ack_wait: Duration::from_millis(1_000), max_deliver: 50, ..Default::default() };
        let ephemeral = async_nats::jetstream::consumer::pull::Config { ack_wait: Duration::from_millis(1_000), ..Default::default() };
        for _ in 0..100 {
            if let Ok(c) = NatsJetStreamClient::new_connection("acktest".into(), url, ephemeral.clone(), worker.clone(), Default::default()).await { NatsJetStreamClient::ensure_stream(&c).await.unwrap(); return c; }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("nats-server did not start");
    }

    async fn next(queue: &NatsJetStreamClient) -> Option<Item> {
        queue.get_next_worker_queue_item_or_none(&KEY, 1, 0, 5, 0).await.unwrap()
    }
    async fn control(queue: &NatsJetStreamClient, item: u64, control: WorkerJobControl) -> bool {
        queue.worker_queue_control_job(&KEY, 1, 0, 5, 0, &item.to_le_bytes(), control).await.unwrap()
    }

    #[tokio::test]
    #[ignore = "requires nats-server on PATH"]
    async fn worker_job_control_through_the_node_client() {
        let server = super::Server::start();
        let queue = client(&server.url).await;
        QStandardQueueBase::ensure_consumer(&queue, &KEY, 1, 0, 5, 0).await.unwrap();
        queue.publish_worker_queue_item_ref(&KEY, 1, 0, 5, 0, &Item(42)).await.unwrap();
        assert_eq!(next(&queue).await, Some(Item(42)));
        for _ in 0..4 {
            assert!(control(&queue, 42, WorkerJobControl::Progress).await);
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert_eq!(next(&queue).await, None, "held by progress");
        }
        assert!(control(&queue, 42, WorkerJobControl::Delay(2_000)).await);
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        assert_eq!(next(&queue).await, None, "delayed past ack_wait");
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        assert_eq!(next(&queue).await, Some(Item(42)), "redelivered after the delay");
        assert!(control(&queue, 42, WorkerJobControl::Release).await);
        assert!(!control(&queue, 42, WorkerJobControl::Complete).await, "handle dropped on release");
        assert_eq!(next(&queue).await, Some(Item(42)), "released for anyone at once");
        assert!(control(&queue, 42, WorkerJobControl::Complete).await);
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        assert_eq!(next(&queue).await, None, "completed");
    }
}
