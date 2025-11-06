use async_trait::async_trait;
use parth_core::{data::queue::queue_key::{PCoreQueueItemBase, PCoreStandardQueueKeyForRealm, QPBaseQueueType}, QCoreProcCheckpointUniqueId};
use psy_node_core::queue::{ephemeral::{QStandardEphemeralQueuePublisher, QStandardEphemeralQueueSubscriber}, worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber}};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use async_nats::{jetstream::{
    self,
    consumer::{pull::Config as PullConfig, PullConsumer},
    kv::Store,
}, Subject, ToServerAddrs};
use bytes::Bytes;
use futures::{future::try_join_all, stream::StreamExt};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JetStreamAckMode {
    AckEach = 0,
    NoAck = 1,
    AckBatchLast = 2,
}
pub struct NatsJetStreamClient {
    pub base_namespace: String,
    pub jetstream: Arc<jetstream::Context>,
    pub timeout_ms: u64,
    pub stream_name: String,
    pub standard_ephemeral_queue_pull_config: PullConfig,
    pub worker_queue_pull_config: PullConfig,
    pub standard_jet_stream_config: jetstream::stream::Config,
    kv: Store,
}

impl NatsJetStreamClient {
    
    pub async fn new_connection<A: ToServerAddrs>(base_namespace: String, nats_urls: A, standard_ephemeral_queue_pull_config: PullConfig, worker_queue_pull_config: PullConfig, standard_jet_stream_config: jetstream::stream::Config, timeout_ms: u64) -> anyhow::Result<Self> {
        let client = async_nats::connect(nats_urls).await?;
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
            standard_ephemeral_queue_pull_config,
            worker_queue_pull_config,
            standard_jet_stream_config,
            kv,
        })
    }

    pub async fn ensure_stream(&self) -> anyhow::Result<()> {
        let stream_config = jetstream::stream::Config {
            name: self.stream_name.clone(),
            subjects: vec![format!("{}.>", &self.base_namespace)],
            ..self.standard_jet_stream_config.clone()
        };

        if let Err(err) = self.jetstream.get_stream(&self.stream_name).await {
            if !err.to_string().to_lowercase().contains("not found") {
                return Err(err.into());
            }
            self.jetstream.create_stream(stream_config).await?;
        }

        Ok(())
    }
    pub fn get_pull_config_for_queue_type(&self, queue_type: QPBaseQueueType) -> PullConfig {
        match queue_type {
            QPBaseQueueType::StandardEphemeral => self.standard_ephemeral_queue_pull_config.clone(),
            QPBaseQueueType::WorkerQueue => self.worker_queue_pull_config.clone(),
        }
    }

    pub async fn ensure_consumer(&self, subject: &str, durable_name: &str, queue_type: QPBaseQueueType) -> anyhow::Result<()> {
        let config = PullConfig {
            durable_name: Some(durable_name.to_string()),
            filter_subject: subject.to_string(),
            ..self.get_pull_config_for_queue_type(queue_type)
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

    pub async fn ensure_stream_consumer(&self, subject: &str, durable_name: &str, queue_type: QPBaseQueueType) -> anyhow::Result<()> {
        self.ensure_stream().await?;
        self.ensure_consumer(subject, durable_name, queue_type).await
    }
    pub async fn push_messages_dq_bytes(&self, subject: &str, data: &[&[u8]]) -> anyhow::Result<()> {
        self.ensure_stream().await?;

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
    pub async fn push_messages_dq_bytes_vec(&self, subject: &str, data: &[Vec<u8>]) -> anyhow::Result<()> {
        self.ensure_stream().await?;

        const BATCH_SIZE: usize = 1000; // Adjust based on testing; 1000-5000 is a good starting point
        let subject = subject.to_string();

        for chunk in data.chunks(BATCH_SIZE) {
            let mut futs = Vec::with_capacity(chunk.len());
            for job in chunk.iter() {
                futs.push(self.jetstream.publish(subject.clone(), Bytes::copy_from_slice(&job)));
            }
            try_join_all(futs).await?;
        }

        Ok(())
    }
    pub async fn push_messages_dq_bytes_sized<const N: usize>(&self, subject: &str, data: &[[u8; N]]) -> anyhow::Result<()> {
        self.ensure_stream().await?;

        const BATCH_SIZE: usize = 1000; // Adjust based on testing; 1000-5000 is a good starting point
        let subject = subject.to_string();

        for chunk in data.chunks(BATCH_SIZE) {
            let mut futs = Vec::with_capacity(chunk.len());
            for job in chunk.iter() {
                futs.push(self.jetstream.publish(subject.clone(), Bytes::copy_from_slice(&job[..])));
            }
            try_join_all(futs).await?;
        }

        Ok(())
    }

    pub async fn push_messages_dq_qi_ref<QueueItem: PCoreQueueItemBase + Clone + Send + Sync>(&self, subject: &str, data: &[&QueueItem]) -> anyhow::Result<()> {
        self.ensure_stream().await?;

        const BATCH_SIZE: usize = 1000; // Adjust based on testing; 1000-5000 is a good starting point
        let subject = subject.to_string();

        for chunk in data.chunks(BATCH_SIZE) {
            let mut futs = Vec::with_capacity(chunk.len());
            for &job in chunk {
                futs.push(self.jetstream.publish(subject.clone(), Bytes::copy_from_slice(&job.encode_queue_item_vec()?)));
            }
            try_join_all(futs).await?;
        }

        Ok(())
    }
    pub async fn push_messages_dq_qi<QueueItem: PCoreQueueItemBase + Clone + Send + Sync>(&self, subject: &str, data: &[QueueItem]) -> anyhow::Result<()> {
        self.ensure_stream().await?;

        const BATCH_SIZE: usize = 1000; // Adjust based on testing; 1000-5000 is a good starting point
        let subject = subject.to_string();

        for chunk in data.chunks(BATCH_SIZE) {
            let mut futs = Vec::with_capacity(chunk.len());
            for job in chunk {
                futs.push(self.jetstream.publish(subject.clone(), Bytes::copy_from_slice(&job.encode_queue_item_vec()?)));
            }
            try_join_all(futs).await?;
        }

        Ok(())
    }

    pub async fn push_message_dq_qi_ref<QueueItem: PCoreQueueItemBase + Clone + Send + Sync>(&self, subject: &str, data: &QueueItem) -> anyhow::Result<()> {
        self.ensure_stream().await?;
        self.jetstream.publish(subject.to_string(), Bytes::copy_from_slice(&data.encode_queue_item_vec()?)).await?;
        Ok(())
    }
    pub async fn push_messages_dq_qi_owned<QueueItem: PCoreQueueItemBase + Clone + Send + Sync>(&self, subject: &str, data: QueueItem) -> anyhow::Result<()> {
        self.ensure_stream().await?;
        self.jetstream.publish(subject.to_string(), Bytes::copy_from_slice(&data.encode_queue_item_vec()?)).await?;
        Ok(())
    }
    pub async fn dump_queue_dq_qi_batch<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        subject: &str,
        durable_name: &str,
        max_messages_per_batch: usize,
        max_messages_total_to_dump: usize,
        data_vec: &mut Vec<QK::QueueItem>,
    ) -> anyhow::Result<()> {
        self.ensure_stream().await?;
        self.ensure_consumer(subject, &durable_name, QPBaseQueueType::StandardEphemeral).await?;
        let size_hint = QK::QueueItem::get_size_hint();
        let has_fixed_size = QK::QueueItem::has_fixed_size() && size_hint > 0;

        let consumer: PullConsumer = self
            .jetstream
            .get_consumer_from_stream::<PullConfig, _, _>(&durable_name, &self.stream_name)
            .await?;
        let mut messages = consumer.fetch().max_messages(max_messages_per_batch.min(max_messages_total_to_dump)).messages().await?;
        let mut total_messages_dumped = 0;
        if max_messages_total_to_dump == 0 {
            return Ok(());
        }

        let mode = queue_key.get_queue_type();

        let mut last_reply: Option<Subject> = None;
        while let Some(Ok(jet_msg)) = messages.next().await {
            if has_fixed_size && jet_msg.payload.len() != size_hint {
                return Err(anyhow::anyhow!("Invalid queue item data length"));
            }
            total_messages_dumped += 1;

            let job = QK::QueueItem::decode_queue_item_ref(jet_msg.payload.as_ref())?;
            if jet_msg.reply.is_some() {
                if mode == QPBaseQueueType::StandardEphemeral {
                    last_reply = Some(jet_msg.reply.clone().unwrap());
                } else  if mode == QPBaseQueueType::WorkerQueue{
                    let kv_key = format!("{}.{}", subject, hex::encode(job.get_restorable_job_id()));

                    self.kv
                        .put(&kv_key, Bytes::copy_from_slice(jet_msg.reply.as_deref().unwrap().as_bytes()))
                        .await?;
                }
            }else if mode == QPBaseQueueType::WorkerQueue {
                tracing::error!("failed to get a reply/ack for a worker queue job, ignoring");
            }
            data_vec.push(job);
            if total_messages_dumped >= max_messages_total_to_dump {
                break;
            }
        }
        if let Some(reply) = last_reply {
            self.jetstream.publish(reply, Bytes::from_static(b"+ACK")).await?;
        }
        Ok(())
    }

    pub async fn dump_queue_dq_bytes_ephemeral(
        &self,
        subject: &str,
        durable_name: &str,
        ack_mode: JetStreamAckMode,
        max_messages_per_batch: usize,
        max_messages_total_to_dump: usize,
        expected_size: Option<usize>,
        bytes_vec: &mut Vec<Vec<u8>>,
    ) -> anyhow::Result<usize> {
        self.ensure_stream().await?;
        self.ensure_consumer(subject, &durable_name, QPBaseQueueType::StandardEphemeral).await?;
        let has_expected_size = expected_size.is_some();
        let real_expected_size = expected_size.unwrap_or(0);

        let consumer: PullConsumer = self
            .jetstream
            .get_consumer_from_stream::<PullConfig, _, _>(&durable_name, &self.stream_name)
            .await?;
        let mut messages = consumer.fetch().max_messages(max_messages_per_batch).messages().await?;
        let mut total_messages_dumped = 0;
        if max_messages_total_to_dump == 0 {
            return Ok(0);
        }

        let mut last_reply: Option<Subject> = None;


        while let Some(Ok(jet_msg)) = messages.next().await {
            if has_expected_size && jet_msg.payload.len() != real_expected_size {
                return Err(anyhow::anyhow!("Invalid queue item data length"));
            }
            total_messages_dumped += 1;
            bytes_vec.push(jet_msg.payload.to_vec());
            if jet_msg.reply.is_some() {
                if ack_mode == JetStreamAckMode::NoAck {
                    // no-op
                } else if ack_mode == JetStreamAckMode::AckEach || (ack_mode == JetStreamAckMode::AckBatchLast && total_messages_dumped >= max_messages_per_batch && max_messages_per_batch != 0) {
                    jet_msg.ack().await.map_err(|e| anyhow::anyhow!("Failed to ACK message: {}", e))?;
                        if ack_mode == JetStreamAckMode::AckBatchLast {
                            last_reply = None;
                        }
                    } else if ack_mode == JetStreamAckMode::AckBatchLast {
                        last_reply = jet_msg.reply.clone();
                    }
                }
            if total_messages_dumped >= max_messages_total_to_dump {
                break;
            }
        }
        if ack_mode == JetStreamAckMode::AckBatchLast {
            if let Some(reply) = last_reply {
                self.jetstream.publish(reply, Bytes::from_static(b"+ACK")).await?;
            }
        }
        Ok(total_messages_dumped)
    }



    pub async fn get_message_if_exists_dq_bytes_ephemeral(&self, subject: &str, durable_name: &str, ack_mode: JetStreamAckMode) -> anyhow::Result<Option<Vec<u8>>> {
        self.ensure_stream().await?;

        self.ensure_consumer(subject, durable_name, QPBaseQueueType::StandardEphemeral).await?;

        let consumer: PullConsumer = self
            .jetstream
            .get_consumer_from_stream::<PullConfig, _, _>(&durable_name, &self.stream_name)
            .await?;

        let request = consumer.fetch().max_messages(1);
        let mut messages = request.messages().await?;

        if let Some(Ok(jet_msg)) = messages.next().await {
            let job = jet_msg.payload.to_vec();
            if ack_mode == JetStreamAckMode::NoAck {
                return Ok(Some(job));
            }else{
                jet_msg.ack().await.map_err(|e| anyhow::anyhow!("Failed to ACK message: {}", e))?;
            }
            Ok(Some(job))
        } else {
            Ok(None)
        }
    }
    pub async fn get_message_if_exists_dq_bytes_ephemeral_qi<QueueItem: PCoreQueueItemBase>(&self, subject: &str, durable_name: &str, ack_mode: JetStreamAckMode) -> anyhow::Result<Option<QueueItem>> {
        self.ensure_stream().await?;

        self.ensure_consumer(subject, durable_name, QPBaseQueueType::StandardEphemeral).await?;

        let consumer: PullConsumer = self
            .jetstream
            .get_consumer_from_stream::<PullConfig, _, _>(&durable_name, &self.stream_name)
            .await?;

        let request = consumer.fetch().max_messages(1);
        let mut messages = request.messages().await?;

        if let Some(Ok(jet_msg)) = messages.next().await {
            let job = QueueItem::decode_queue_item_ref(jet_msg.payload.as_ref())?;
            if ack_mode == JetStreamAckMode::NoAck {
                return Ok(Some(job));
            }else{
                jet_msg.ack().await.map_err(|e| anyhow::anyhow!("Failed to ACK message: {}", e))?;
            }
            Ok(Some(job))
        } else {
            Ok(None)
        }
    }
    pub async fn get_message_if_exists_dqi_worker<QK: PCoreStandardQueueKeyForRealm>(&self, queue_key: &QK, subject: &str, durable_name: &str) -> anyhow::Result<Option<QK::QueueItem>> {
        self.ensure_stream().await?;

        self.ensure_consumer(subject, durable_name, queue_key.get_queue_type()).await?;

        let consumer: PullConsumer = self
            .jetstream
            .get_consumer_from_stream::<PullConfig, _, _>(&durable_name, &self.stream_name)
            .await?;

        let request = consumer.fetch().max_messages(1);
        let mut messages = request.messages().await?;

        let base_queue_type = queue_key.get_queue_type();
        if base_queue_type != QPBaseQueueType::WorkerQueue {
            return Err(anyhow::anyhow!("Invalid queue type for worker queue retrieval"));
        }

        if let Some(Ok(jet_msg)) = messages.next().await {
            let job = QK::QueueItem::decode_queue_item_ref(jet_msg.payload.as_ref())?;
            let kv_key = format!("{}.{}", subject, hex::encode(job.get_restorable_job_id()));
            self.kv
                .put(&kv_key, Bytes::copy_from_slice(jet_msg.reply.as_deref().unwrap().as_bytes()))
                .await?;
            Ok(Some(job))
        } else {
            Ok(None)
        }
    }

    pub async fn report_message_completed_dq(&self, subject: &str, report_id: &[u8]) -> anyhow::Result<bool> {
        let kv_key = format!("{}.{}", subject, hex::encode(report_id));
        if let Some(reply_bytes) = self.kv.get(&kv_key).await? {
            let reply = String::from_utf8(reply_bytes.to_vec())?;
            self.jetstream.publish(reply, Bytes::from_static(b"+ACK")).await?;
            self.kv.delete(&kv_key).await?;
            return Ok(true);
        }else{
            return Ok(false);
        }
    }


    pub async fn wait_until_all_jobs_complete_or_timeout_dq(&self, subject: &str, durable_name: &str, queue_type: QPBaseQueueType, timeout_ms: u64) -> anyhow::Result<()> {
        self.ensure_stream_consumer(subject, durable_name, queue_type).await?;

        let start = Instant::now();
        let max_wait: Duration = Duration::from_millis(timeout_ms);

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

}


#[async_trait]
impl QStandardEphemeralQueuePublisher for NatsJetStreamClient {
    async fn publish_ephemeral_queue_item_bytes_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        item_bytes: &[u8],
    ) -> anyhow::Result<()> {
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        self.push_messages_dq_bytes(&subject, &[item_bytes]).await?;

        Ok(())
    }
    async fn publish_many_ephemeral_queue_items_bytes_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items_bytes: &[&[u8]],
    ) -> anyhow::Result<()> {
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        self.push_messages_dq_bytes(&subject, items_bytes).await?;

        Ok(())
    }
    async fn publish_ephemeral_queue_item_owned_bytes<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        item_bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        self.push_messages_dq_bytes(&subject, &[&item_bytes]).await?;

        Ok(())
    }
    async fn publish_many_ephemeral_queue_items_owned_bytes<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items_bytes: Vec<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let item_refs: Vec<&[u8]> = items_bytes.iter().map(|v| v.as_slice()).collect();
        self.push_messages_dq_bytes(&subject, &item_refs).await?;

        Ok(())
    }
    async fn publish_ephemeral_queue_item_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        item: &QK::QueueItem,
    ) -> anyhow::Result<()> {
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        self.push_message_dq_qi_ref(&subject, item).await?;

        Ok(())
    }
    async fn publish_many_ephemeral_queue_items_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items: &[&QK::QueueItem],
    ) -> anyhow::Result<()> {
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        self.push_messages_dq_qi_ref(&subject, items).await?;

        Ok(())
    }
    async fn publish_ephemeral_queue_item_owned<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        item: QK::QueueItem,
    ) -> anyhow::Result<()> {
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        self.push_messages_dq_qi_owned(&subject, item).await?;

        Ok(())
    }

    async fn publish_many_ephemeral_queue_items<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items: &[QK::QueueItem],
    ) -> anyhow::Result<()>{
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        self.push_messages_dq_qi(&subject, items).await?;

        Ok(())

    }
    async fn publish_many_ephemeral_queue_items_owned<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items: Vec<QK::QueueItem>,
    ) -> anyhow::Result<()> {
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        self.push_messages_dq_qi(&subject, &items).await?;

        Ok(())
    }
}

#[async_trait]
impl QStandardEphemeralQueueSubscriber for NatsJetStreamClient {
    async fn wait_for_ephemeral_queue_item_bytes<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        timeout_ms: u64,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let durable_name = queue_key.get_durable_name(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let start_time = Instant::now();
        let timeout_duration = Duration::from_millis(timeout_ms);
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Some(msg) = self.get_message_if_exists_dq_bytes_ephemeral(&subject, &durable_name, JetStreamAckMode::AckEach).await? {
                        return Ok(Some(msg));
                    }
                    if start_time.elapsed() >= timeout_duration {
                        return Ok(None);
                    }
                }
            }
        }
    }
    async fn wait_for_ephemeral_queue_item<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        timeout_ms: u64,
    ) -> anyhow::Result<Option<QK::QueueItem>> {
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let durable_name = queue_key.get_durable_name(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let start_time = Instant::now();
        let timeout_duration = Duration::from_millis(timeout_ms);
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Some(msg) = self.get_message_if_exists_dq_bytes_ephemeral_qi(&subject, &durable_name, JetStreamAckMode::AckEach).await? {
                        return Ok(Some(msg));
                    }
                    if start_time.elapsed() >= timeout_duration {
                        return Ok(None);
                    }
                }
            }
        }
    }
    async fn dump_entire_ephemeral_queue_bytes<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        max_items: usize,
    ) -> anyhow::Result<Vec<Vec<u8>>> {
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let durable_name = queue_key.get_durable_name(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let mut bytes_vec: Vec<Vec<u8>> = Vec::new();
        let mut total = self.dump_queue_dq_bytes_ephemeral(&subject, &durable_name, JetStreamAckMode::AckBatchLast, 1000, max_items, None, &mut bytes_vec).await?;

        let mut total_dumped = total;
        while total != 0 && total_dumped < max_items {
            total = self.dump_queue_dq_bytes_ephemeral(&subject, &durable_name, JetStreamAckMode::AckBatchLast, 1000, max_items - total_dumped, None, &mut bytes_vec).await?;
            total_dumped += total;
        }
        Ok(bytes_vec)
    }
    async fn dump_entire_ephemeral_queue<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        max_items: usize,
    ) -> anyhow::Result<Vec<QK::QueueItem>> {
        if max_items == 0 {
            return Ok(Vec::new());
        }
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let durable_name = queue_key.get_durable_name(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let mut items: Vec<QK::QueueItem> = Vec::new();
        const BATCH_SIZE: usize = 1000;
        let size_hint = QK::QueueItem::get_size_hint();
        let has_fixed_size = QK::QueueItem::has_fixed_size() && size_hint > 0;
        
        let real_batch_size = BATCH_SIZE.min(max_items);
        let mut total_items_dumped = 0usize;
        self.ensure_stream().await?;
        self.ensure_consumer(&subject, &durable_name, QPBaseQueueType::StandardEphemeral).await?;


        let consumer: PullConsumer = self
            .jetstream
            .get_consumer_from_stream::<PullConfig, _, _>(&durable_name, &self.stream_name)
            .await?;
        while total_items_dumped < max_items {
            let mut messages = consumer.fetch().max_messages(real_batch_size.min(max_items - total_items_dumped)).messages().await?;
            let mut last_reply = None;

           let mut total_dumped_for_batch = 0;
            while let Some(Ok(jet_msg)) = messages.next().await {
                if total_items_dumped >= max_items {
                    break;
                }
                if has_fixed_size && jet_msg.payload.len() != size_hint {
                    return Err(anyhow::anyhow!("Invalid queue item data length"));
                }

                let job = QK::QueueItem::decode_queue_item_ref(jet_msg.payload.as_ref())?;
                items.push(job);
                
                if jet_msg.reply.is_some() {
                    last_reply = Some(jet_msg.reply.clone().unwrap());
                }
                total_items_dumped += 1;
                total_dumped_for_batch += 1;
            }
            if let Some(reply) = last_reply {
                self.jetstream.publish(reply, Bytes::from_static(b"+ACK")).await?;
            }
            if total_dumped_for_batch == 0 {
                break;
            }
        }

        Ok(items)
    }
    async fn consume_ephemeral_queue_item_or_none_bytes<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let durable_name = queue_key.get_durable_name(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        self.get_message_if_exists_dq_bytes_ephemeral(&subject, &durable_name, JetStreamAckMode::AckEach).await
    }
    async fn consume_ephemeral_queue_item_or_none<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
    ) -> anyhow::Result<Option<QK::QueueItem>> {
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let durable_name = queue_key.get_durable_name(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);

        self.get_message_if_exists_dq_bytes_ephemeral_qi(&subject, &durable_name, JetStreamAckMode::AckEach).await
    }
}




#[async_trait]
impl QStandardWorkerQueuePublisher for NatsJetStreamClient {
    async fn publish_worker_queue_item_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        item: &QK::QueueItem,
    ) -> anyhow::Result<()>{
        self.push_message_dq_qi_ref(&queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group), item).await
    }
    async fn publish_many_worker_queue_items_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items: &[&QK::QueueItem],
    ) -> anyhow::Result<()>{
        self.push_messages_dq_qi_ref(&queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group), items).await
    }
    async fn publish_worker_queue_item_owned<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        item: QK::QueueItem,
    ) -> anyhow::Result<()>{
        self.push_messages_dq_qi_owned(&queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group), item).await
    }
    async fn publish_many_worker_queue_items_owned<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items: Vec<QK::QueueItem>,
    ) -> anyhow::Result<()>{
        self.push_messages_dq_qi(&queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group), &items).await
    }
    async fn publish_many_worker_queue_items<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items: &[QK::QueueItem],
    ) -> anyhow::Result<()>{
        self.push_messages_dq_qi(&queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group), items).await
    }
}
#[async_trait]
impl QStandardWorkerQueueSubscriber for NatsJetStreamClient {
    async fn wait_for_worker_queue_item<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        timeout_ms: u64,
    ) -> anyhow::Result<Option<QK::QueueItem>>{
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let durable_name = queue_key.get_durable_name(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let start_time = Instant::now();
        let timeout_duration = Duration::from_millis(timeout_ms);
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Some(msg) = self.get_message_if_exists_dq_bytes_ephemeral_qi(&subject, &durable_name, JetStreamAckMode::AckEach).await? {
                        return Ok(Some(msg));
                    }
                    if start_time.elapsed() >= timeout_duration {
                        return Ok(None);
                    }
                }
            }
        }
    }
    async fn dump_entire_worker_queue<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        max_items: usize,
    ) -> anyhow::Result<Vec<QK::QueueItem>>{
        if max_items == 0 {
            return Ok(Vec::new());
        }
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let durable_name = queue_key.get_durable_name(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        self.ensure_stream().await?;
        self.ensure_consumer(&subject, &durable_name, QPBaseQueueType::StandardEphemeral).await?;
        let size_hint = QK::QueueItem::get_size_hint();
        let has_fixed_size = QK::QueueItem::has_fixed_size() && size_hint > 0;

        let consumer: PullConsumer = self
            .jetstream
            .get_consumer_from_stream::<PullConfig, _, _>(&durable_name, &self.stream_name)
            .await?;
        const BATCH_SIZE: usize = 1000;
        let max_messages_per_batch = BATCH_SIZE.min(max_items);
        let max_messages_total_to_dump = max_items;
        let mut total_messages_dumped = 0;

        let mode = queue_key.get_queue_type();
        if mode != QPBaseQueueType::WorkerQueue {
            return Err(anyhow::anyhow!("Invalid queue type for worker queue dump"));
        }

        let mut data_vec = Vec::with_capacity(1000);

        let mut total_dumped_for_batch: usize;
        while total_messages_dumped < max_items {

            let mut messages = consumer.fetch().max_messages(max_messages_per_batch.min(max_items)).messages().await?;
            total_dumped_for_batch = 0;
            while let Some(Ok(jet_msg)) = messages.next().await {
                if has_fixed_size && jet_msg.payload.len() != size_hint {
                    return Err(anyhow::anyhow!("Invalid queue item data length"));
                }

                let job = QK::QueueItem::decode_queue_item_ref(jet_msg.payload.as_ref())?;
                if jet_msg.reply.is_some() {
                        let kv_key = format!("{}.{}", subject, hex::encode(job.get_restorable_job_id()));

                        self.kv
                            .put(&kv_key, Bytes::copy_from_slice(jet_msg.reply.as_deref().unwrap().as_bytes()))
                            .await?;
                }else {
                    tracing::error!("failed to get a reply/ack for a worker queue job, ignoring");
                    total_messages_dumped-=1;
                    continue;
                }
                total_messages_dumped += 1;
                total_dumped_for_batch += 1;
                data_vec.push(job);
                if total_messages_dumped >= max_messages_total_to_dump {
                    break;
                }
            }
            if total_dumped_for_batch == 0 {
                break;
            }
        }
        Ok(data_vec)
    }
    async fn get_next_worker_queue_item_or_none<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
    ) -> anyhow::Result<Option<QK::QueueItem>>{
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let durable_name = queue_key.get_durable_name(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        self.get_message_if_exists_dqi_worker(queue_key, &subject, &durable_name).await
    }
    async fn wait_until_all_jobs_complete_or_timeout_worker<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_topic: u128,
        task_group: u32,
        timeout_ms: u64,
    ) -> anyhow::Result<()>{
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_topic, task_group);
        let durable_name = queue_key.get_durable_name(&self.base_namespace, realm_id, realm_sub_id, unique_topic, task_group);
        self.wait_until_all_jobs_complete_or_timeout_dq(&subject, &durable_name, queue_key.get_queue_type(), timeout_ms).await
    }
    
    async fn worker_queue_report_job_completed<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_topic: u128,
        task_group: u32,
        item: &QK::QueueItem,
    ) -> anyhow::Result<bool> {
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_topic, task_group);
        self.report_message_completed_dq(&subject, &item.get_restorable_job_id()).await
    }
}
