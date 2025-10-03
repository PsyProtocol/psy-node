use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use async_nats::{
    jetstream::{
        self,
        consumer::{pull::Config as PullConfig, PullConsumer},
        kv::Store,
    },
    Client,
};
use bytes::Bytes;
use futures::{future::try_join_all, stream::StreamExt};
use rand::{thread_rng, RngCore};

pub struct NatsJetStreamClient {
    pub base_namespace: String,
    pub jetstream: Arc<jetstream::Context>,
    pub timeout_ms: u64,
    stream_name: String,
    kv: Store,
}

pub type QueueJobData = [u8; 24];

pub fn random_job_data() -> QueueJobData {
    let mut data = [0u8; 24];
    let mut rand = thread_rng();
    rand.fill_bytes(&mut data);
    data
}

impl NatsJetStreamClient {
    pub async fn new_connection(base_namespace: String, nats_url: String, timeout_ms: u64) -> anyhow::Result<Self> {
        let client = async_nats::connect(nats_url).await?;
        let jetstream_ctx = jetstream::new(client);
        let jetstream = Arc::new(jetstream_ctx);

        let stream_name = format!("{}_stream", base_namespace.replace('.', "_"));
        let bucket = format!("{}_kv", base_namespace.replace('.', "_"));

        let kv = match jetstream.get_key_value(&bucket).await {
            Ok(kv) => kv,
            Err(_) => {
                jetstream
                    .create_key_value(jetstream::kv::Config {
                        bucket,
                        ..Default::default()
                    })
                    .await?
            }
        };

        Ok(Self {
            base_namespace,
            jetstream,
            timeout_ms,
            stream_name,
            kv,
        })
    }

    async fn ensure_stream(&self) -> anyhow::Result<()> {
        let stream_config = jetstream::stream::Config {
            name: self.stream_name.clone(),
            subjects: vec![format!("{}.>", &self.base_namespace)],
            ..Default::default()
        };

        if let Err(err) = self.jetstream.get_stream(&self.stream_name).await {
            if !err.to_string().to_lowercase().contains("not found") {
                return Err(err.into());
            }
            self.jetstream.create_stream(stream_config).await?;
        }

        Ok(())
    }

    async fn ensure_consumer(&self, subject: &str, durable_name: &str) -> anyhow::Result<()> {
        let config = PullConfig {
            durable_name: Some(durable_name.to_string()),
            filter_subject: subject.to_string(),
            ack_policy: jetstream::consumer::AckPolicy::Explicit,
            ack_wait: Duration::from_millis(self.timeout_ms),
            max_deliver: 20,
            replay_policy: jetstream::consumer::ReplayPolicy::Instant,
            deliver_policy: jetstream::consumer::DeliverPolicy::All,
            max_ack_pending: 100000,
            ..Default::default()
        };

        if let Err(err) = self
            .jetstream
            .get_consumer_from_stream::<PullConfig, _, _>(durable_name, &self.stream_name)
            .await
        {
            if !err.to_string().to_lowercase().contains("not found") {
                return Err(err.into());
            }
            self.jetstream.create_consumer_on_stream(config, &self.stream_name).await?;
        }

        Ok(())
    }

    pub fn get_queue_subject(&self, realm_id: u64, realm_sub_id: u64, queue_type: u32, unique_topic: u128, task_group: u64) -> String {
        format!(
            "{}.r{}_{}.qt{}.u{:x}.g{}",
            self.base_namespace, realm_id, realm_sub_id, queue_type, unique_topic, task_group
        )
    }
    pub async fn push_messages_dq(&self, subject: &str, data: &[QueueJobData]) -> anyhow::Result<()> {
        self.ensure_stream().await?;

        let durable_name = subject.replace('.', "_");
        self.ensure_consumer(subject, &durable_name).await?;

        const BATCH_SIZE: usize = 1000; // Adjust based on testing; 1000-5000 is a good starting point
        let subject = subject.to_string();

        for chunk in data.chunks(BATCH_SIZE) {
            let mut futs = Vec::with_capacity(chunk.len());
            for &job in chunk {
                futs.push(self.jetstream.publish(subject.clone(), Bytes::copy_from_slice(&job)));
            }
            try_join_all(futs).await?;
        }

        Ok(())
    }

    /*
    pub async fn push_messages_dq(&self, subject: &str, data: &[QueueJobData]) -> anyhow::Result<()> {
        self.ensure_stream().await?;

        let durable_name = subject.replace('.', "_");
        self.ensure_consumer(subject, &durable_name).await?;

        let subject = subject.to_string();
        let mut futs = Vec::with_capacity(data.len());
        for &job in data {
            futs.push(self.jetstream.publish(subject.clone(), Bytes::copy_from_slice(&job)));
        }
        try_join_all(futs).await?;

        Ok(())
    }
    */

    pub async fn push_messages(
        &self,
        realm_id: u64,
        realm_sub_id: u64,
        queue_type: u32,
        unique_topic: u128,
        task_group: u64,
        data: &[QueueJobData],
    ) -> anyhow::Result<()> {
        let subject = self.get_queue_subject(realm_id, realm_sub_id, queue_type, unique_topic, task_group);
        self.push_messages_dq(&subject, data).await
    }

    pub async fn get_message_if_exists_dq(&self, subject: &str) -> anyhow::Result<Option<QueueJobData>> {
        self.ensure_stream().await?;

        let durable_name = subject.replace('.', "_");
        self.ensure_consumer(subject, &durable_name).await?;

        let consumer: PullConsumer = self
            .jetstream
            .get_consumer_from_stream::<PullConfig, _, _>(&durable_name, &self.stream_name)
            .await?;

        let request = consumer.fetch().max_messages(1);
        let mut messages = request.messages().await?;

        if let Some(Ok(jet_msg)) = messages.next().await {
            if jet_msg.payload.len() != 24 {
                return Err(anyhow::anyhow!("Invalid job data length"));
            }
            let mut job = [0u8; 24];
            job.copy_from_slice(&jet_msg.payload);
            let kv_key = format!("{}.{}", subject, hex::encode(job));
            if jet_msg.reply.is_none() {
                return Err(anyhow::anyhow!("Message reply is empty, cannot track completion"));
            } else {
                self.kv
                    .put(&kv_key, Bytes::copy_from_slice(jet_msg.reply.as_deref().unwrap().as_bytes()))
                    .await?;
            }

            Ok(Some(job))
        } else {
            Ok(None)
        }
    }

    pub async fn get_message_if_exists(
        &self,
        realm_id: u64,
        realm_sub_id: u64,
        queue_type: u32,
        unique_topic: u128,
        task_group: u64,
    ) -> anyhow::Result<Option<QueueJobData>> {
        let subject = self.get_queue_subject(realm_id, realm_sub_id, queue_type, unique_topic, task_group);
        self.get_message_if_exists_dq(&subject).await
    }

    pub async fn report_message_completed_dq(&self, subject: &str, job_id: QueueJobData) -> anyhow::Result<()> {
        let kv_key = format!("{}.{}", subject, hex::encode(job_id));
        if let Some(reply_bytes) = self.kv.get(&kv_key).await? {
            let reply = String::from_utf8(reply_bytes.to_vec())?;
            self.jetstream.publish(reply, Bytes::from_static(b"+ACK")).await?;
            self.kv.delete(&kv_key).await?;
        }
        Ok(())
    }

    pub async fn report_message_completed(
        &self,
        realm_id: u64,
        realm_sub_id: u64,
        queue_type: u32,
        unique_topic: u128,
        task_group: u64,
        job_id: QueueJobData,
    ) -> anyhow::Result<()> {
        let subject = self.get_queue_subject(realm_id, realm_sub_id, queue_type, unique_topic, task_group);
        self.report_message_completed_dq(&subject, job_id).await
    }

    pub async fn wait_until_all_jobs_complete_or_timeout_dq(&self, subject: &str) -> anyhow::Result<()> {
        self.ensure_stream().await?;

        let durable_name = subject.replace('.', "_");
        self.ensure_consumer(subject, &durable_name).await?;

        let start = Instant::now();
        let max_wait: Duration = Duration::from_millis(1000 * self.timeout_ms);

        loop {
            let mut consumer: PullConsumer = self
                .jetstream
                .get_consumer_from_stream::<PullConfig, _, _>(&durable_name, &self.stream_name)
                .await?;
            let info = consumer.info().await?;
            if info.num_pending == 0 && info.num_ack_pending == 0 {
                return Ok(());
            }
            if start.elapsed() > max_wait {
                return Err(anyhow::anyhow!("Timeout waiting for all jobs to complete"));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    pub async fn wait_until_all_jobs_complete_or_timeout(
        &self,
        realm_id: u64,
        realm_sub_id: u64,
        queue_type: u32,
        unique_topic: u128,
        task_group: u64,
    ) -> anyhow::Result<()> {
        let subject = self.get_queue_subject(realm_id, realm_sub_id, queue_type, unique_topic, task_group);
        self.wait_until_all_jobs_complete_or_timeout_dq(&subject).await
    }
}
