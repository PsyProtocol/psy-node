use std::{
    sync::Arc,
    time::{Duration, Instant},
    collections::HashMap,
};

use async_nats::{
    Subject, ToServerAddrs, jetstream::{
        self, consumer::{PullConsumer, pull::Config as PullConfig}, kv::Store
    }
};
use tokio::sync::RwLock;
use async_trait::async_trait;
use moka::future::Cache;
use bytes::Bytes;
use cf_utils::timer::DebugTimer;
use futures::{future::try_join_all, stream::StreamExt};
use parth_core::{
    data::queue::queue_key::{PCoreQueueItemBase, PCoreStandardQueueKeyForRealm, QPBaseQueueType},
    QCoreProcCheckpointUniqueId,
};
use psy_node_core::queue::{
    infrastructure::QStandardQueueBase,
    ephemeral::{QStandardEphemeralQueuePublisher, QStandardEphemeralQueueSubscriber},
    worker_queue::{QStandardWorkerQueue, QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JetStreamAckMode {
    AckEach = 0,
    NoAck = 1,
    AckBatchLast = 2,
}

fn worker_queue_completion_reached(
    num_pending: u64,
    num_ack_pending: usize,
    delivered_stream_sequence: u64,
    ack_floor_stream_sequence: u64,
    required_ack_stream_sequence: u64,
) -> bool {
    num_pending == 0
        && num_ack_pending == 0
        && delivered_stream_sequence >= required_ack_stream_sequence
        && ack_floor_stream_sequence >= required_ack_stream_sequence
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NatsWorkerQueuePublishBarrier {
    min_stream_sequence: Option<u64>,
    max_stream_sequence: Option<u64>,
    message_count: usize,
}

impl NatsWorkerQueuePublishBarrier {
    fn record_ack(&mut self, stream_sequence: u64) {
        self.min_stream_sequence = Some(
            self.min_stream_sequence
                .map_or(stream_sequence, |current| current.min(stream_sequence)),
        );
        self.max_stream_sequence = Some(
            self.max_stream_sequence
                .map_or(stream_sequence, |current| current.max(stream_sequence)),
        );
        self.message_count += 1;
    }

    fn is_empty(&self) -> bool {
        self.message_count == 0
    }

    fn required_ack_stream_sequence(&self) -> Option<u64> {
        self.max_stream_sequence
    }

    pub fn message_count(&self) -> usize {
        self.message_count
    }

    pub fn max_stream_sequence(&self) -> Option<u64> {
        self.max_stream_sequence
    }
}

fn consumer_missing_with_barrier(
    subject: &str,
    durable_name: &str,
    barrier: &NatsWorkerQueuePublishBarrier,
) -> anyhow::Result<()> {
    if barrier.is_empty() {
        return Ok(());
    }

    anyhow::bail!(
        "Worker consumer missing before publication barrier completed: subject={}, durable_name={}, publish_max_stream_sequence={:?}, message_count={}",
        subject,
        durable_name,
        barrier.max_stream_sequence,
        barrier.message_count,
    )
}
pub struct NatsJetStreamClient {
    pub base_namespace: String,
    pub jetstream: Arc<jetstream::Context>,
    pub stream_name: String,
    pub standard_ephemeral_queue_pull_config: PullConfig,
    pub worker_queue_pull_config: PullConfig,
    pub standard_jet_stream_config: jetstream::stream::Config,
    kv: Store,
    consumer_cache: Cache<String, PullConsumer>,
}

impl NatsJetStreamClient {
    fn consumer_cache_key(&self, durable_name: &str) -> String {
        format!("{}:{}", self.stream_name, durable_name)
    }

    fn is_consumer_not_found_error(err: &(impl std::fmt::Display + ?Sized)) -> bool {
        let err_string = err.to_string().to_lowercase();
        err_string.contains("consumer not found") || err_string.contains("error code 10014")
    }

    async fn invalidate_consumer_cache(&self, durable_name: &str) {
        self.consumer_cache
            .invalidate(&self.consumer_cache_key(durable_name))
            .await;
    }

    pub async fn new_connection<A: ToServerAddrs>(
        base_namespace: String,
        nats_urls: A,
        standard_ephemeral_queue_pull_config: PullConfig,
        worker_queue_pull_config: PullConfig,
        standard_jet_stream_config: jetstream::stream::Config,
    ) -> anyhow::Result<Self> {
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

        let consumer_cache = Cache::builder()
            .max_capacity(100)
            .time_to_idle(Duration::from_secs(300))
            .build();

        Ok(Self {
            base_namespace,
            jetstream,
            stream_name,
            standard_ephemeral_queue_pull_config,
            worker_queue_pull_config,
            standard_jet_stream_config,
            kv,
            consumer_cache,
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

    async fn get_consumer_cached(&self, durable_name: &str) -> anyhow::Result<PullConsumer> {
        let cache_key = self.consumer_cache_key(durable_name);

        if let Some(consumer) = self.consumer_cache.get(&cache_key).await {
            return Ok(consumer);
        }

        match self
            .jetstream
            .get_consumer_from_stream::<PullConfig, _, _>(durable_name, &self.stream_name)
            .await
        {
            Ok(consumer) => {
                self.consumer_cache.insert(cache_key, consumer.clone()).await;
                Ok(consumer)
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn get_pull_config_for_queue_type(&self, queue_type: QPBaseQueueType) -> PullConfig {
        match queue_type {
            QPBaseQueueType::StandardEphemeral => self.standard_ephemeral_queue_pull_config.clone(),
            QPBaseQueueType::WorkerQueue => self.worker_queue_pull_config.clone(),
        }
    }

    pub async fn ensure_consumer(&self, subject: &str, durable_name: &str, queue_type: QPBaseQueueType) -> anyhow::Result<()> {
        let cache_key = self.consumer_cache_key(durable_name);

        if let Some(mut consumer) = self.consumer_cache.get(&cache_key).await {
            match consumer.info().await {
                Ok(_) => return Ok(()),
                Err(err) if Self::is_consumer_not_found_error(&err) => {
                    tracing::warn!(
                        "cached NATS consumer no longer exists, recreating: stream={}, durable={}",
                        self.stream_name,
                        durable_name
                    );
                    self.consumer_cache.invalidate(&cache_key).await;
                }
                Err(err) => return Err(err.into()),
            }
        }

        let config = PullConfig {
            durable_name: Some(durable_name.to_string()),
            filter_subject: subject.to_string(),
            ..self.get_pull_config_for_queue_type(queue_type)
        };

        let consumer = self.jetstream.create_consumer_on_stream(config, &self.stream_name).await?;
        self.consumer_cache.insert(cache_key, consumer).await;
        Ok(())
    }

    pub async fn ensure_stream_consumer(&self, subject: &str, durable_name: &str, queue_type: QPBaseQueueType) -> anyhow::Result<()> {
        self.ensure_stream().await?;
        self.ensure_consumer(subject, durable_name, queue_type).await
    }

    async fn delete_consumer_by_durable_name(&self, durable_name: &str) -> anyhow::Result<()> {
        self.invalidate_consumer_cache(durable_name).await;

        match self
            .jetstream
            .delete_consumer_from_stream(durable_name, &self.stream_name)
            .await
        {
            Ok(_) => Ok(()),
            Err(err) => {
                if Self::is_consumer_not_found_error(&err) || err.to_string().to_lowercase().contains("not found") {
                    Ok(())
                } else {
                    Err(err.into())
                }
            }
        }
    }

    async fn delete_consumer_for_queue<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
    ) -> anyhow::Result<()> {
        let durable_name = queue_key.get_durable_name(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        self.delete_consumer_by_durable_name(&durable_name).await
    }

    pub async fn push_messages_dq_bytes(&self, subject: &str, data: &[&[u8]]) -> anyhow::Result<()> {

        const BATCH_SIZE: usize = 1000; // Adjust based on testing; 1000-5000 is a good starting point
        let subject = subject.to_string();

        for chunk in data.chunks(BATCH_SIZE) {
            let mut futs = Vec::with_capacity(chunk.len());
            for &job in chunk {
                futs.push(self.jetstream.publish(subject.clone(), Bytes::copy_from_slice(&job)));
            }
            let ack_futures = try_join_all(futs).await?;
            for ack_future in ack_futures {
                ack_future.await?;
            }
        }

        Ok(())
    }
    pub async fn push_messages_dq_bytes_vec(&self, subject: &str, data: &[Vec<u8>]) -> anyhow::Result<()> {

        const BATCH_SIZE: usize = 1000; // Adjust based on testing; 1000-5000 is a good starting point
        let subject = subject.to_string();

        for chunk in data.chunks(BATCH_SIZE) {
            let mut futs = Vec::with_capacity(chunk.len());
            for job in chunk.iter() {
                futs.push(self.jetstream.publish(subject.clone(), Bytes::copy_from_slice(&job)));
            }
            let ack_futures = try_join_all(futs).await?;
            for ack_future in ack_futures {
                ack_future.await?;
            }
        }

        Ok(())
    }
    pub async fn push_messages_dq_bytes_sized<const N: usize>(&self, subject: &str, data: &[[u8; N]]) -> anyhow::Result<()> {

        const BATCH_SIZE: usize = 1000; // Adjust based on testing; 1000-5000 is a good starting point
        let subject = subject.to_string();

        for chunk in data.chunks(BATCH_SIZE) {
            let mut futs = Vec::with_capacity(chunk.len());
            for job in chunk.iter() {
                futs.push(self.jetstream.publish(subject.clone(), Bytes::copy_from_slice(&job[..])));
            }
            let ack_futures = try_join_all(futs).await?;
            for ack_future in ack_futures {
                ack_future.await?;
            }
        }

        Ok(())
    }

    pub async fn push_messages_dq_qi_ref<QueueItem: PCoreQueueItemBase + Clone + Send + Sync>(
        &self,
        subject: &str,
        data: &[&QueueItem],
    ) -> anyhow::Result<()> {

        const BATCH_SIZE: usize = 1000; // Adjust based on testing; 1000-5000 is a good starting point
        let subject = subject.to_string();

        for chunk in data.chunks(BATCH_SIZE) {
            let mut futs = Vec::with_capacity(chunk.len());
            for &job in chunk {
                futs.push(
                    self.jetstream
                        .publish(subject.clone(), Bytes::copy_from_slice(&job.encode_queue_item_vec()?)),
                );
            }
            // NOTE: This function does NOT wait for ack - only waits for publish to complete
            try_join_all(futs).await?;
        }

        Ok(())
    }
    pub async fn push_messages_dq_qi<QueueItem: PCoreQueueItemBase + Clone + Send + Sync>(
        &self,
        subject: &str,
        data: &[QueueItem],
    ) -> anyhow::Result<()> {

        const BATCH_SIZE: usize = 1000; // Adjust based on testing; 1000-5000 is a good starting point
        let subject = subject.to_string();
        println!("Publishing {} items to subject: {}", data.len(), subject);
        for chunk in data.chunks(BATCH_SIZE) {
            let mut futs = Vec::with_capacity(chunk.len());
            for job in chunk {
                futs.push(
                    self.jetstream
                        .publish(subject.clone(), Bytes::copy_from_slice(&job.encode_queue_item_vec()?)),
                );
            }
            let ack_futures = try_join_all(futs).await?;
            for ack_future in ack_futures {
                ack_future.await?;
            }
        }

        Ok(())
    }

    pub async fn push_message_dq_qi_ref<QueueItem: PCoreQueueItemBase + Clone + Send + Sync>(
        &self,
        subject: &str,
        data: &QueueItem,
    ) -> anyhow::Result<()> {
        println!("Publishing to subject: {}", subject);
        self.jetstream
            .publish(subject.to_string(), Bytes::copy_from_slice(&data.encode_queue_item_vec()?))
            .await?
            .await?;
        Ok(())
    }
    pub async fn push_messages_dq_qi_owned<QueueItem: PCoreQueueItemBase + Clone + Send + Sync>(
        &self,
        subject: &str,
        data: QueueItem,
    ) -> anyhow::Result<()> {
        // NOTE: This function does NOT wait for ack - only waits for publish to complete
        self.jetstream
            .publish(subject.to_string(), Bytes::copy_from_slice(&data.encode_queue_item_vec()?))
            .await?;
        Ok(())
    }

    async fn publish_worker_payloads(
        &self,
        subject: &str,
        payloads: Vec<Bytes>,
    ) -> anyhow::Result<NatsWorkerQueuePublishBarrier> {
        const BATCH_SIZE: usize = 1000;

        let started_at = Instant::now();
        let mut barrier = NatsWorkerQueuePublishBarrier::default();
        for chunk in payloads.chunks(BATCH_SIZE) {
            let publish_futures = chunk.iter().map(|payload| {
                self.jetstream
                    .publish(subject.to_string(), payload.clone())
            });
            let ack_futures = try_join_all(publish_futures).await?;
            for ack_future in ack_futures {
                let ack = ack_future.await?;
                barrier.record_ack(ack.sequence);
            }
        }

        tracing::info!(
            subject,
            job_count = barrier.message_count,
            publish_min_stream_sequence = ?barrier.min_stream_sequence,
            publish_max_stream_sequence = ?barrier.max_stream_sequence,
            elapsed_ms = started_at.elapsed().as_millis(),
            "Worker queue publication acknowledged"
        );
        Ok(barrier)
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
        let size_hint = QK::QueueItem::get_size_hint();
        let has_fixed_size = QK::QueueItem::has_fixed_size() && size_hint > 0;

        let consumer = match self.get_consumer_cached(&durable_name).await {
            Ok(consumer) => consumer,
            Err(err) if Self::is_consumer_not_found_error(&err) => return Ok(()),
            Err(err) => return Err(err),
        };
        let mut messages = match consumer
            .fetch()
            .max_messages(max_messages_per_batch.min(max_messages_total_to_dump))
            .messages()
            .await
        {
            Ok(messages) => messages,
            Err(err) if Self::is_consumer_not_found_error(&err) => {
                self.invalidate_consumer_cache(durable_name).await;
                return Ok(());
            }
            Err(err) => return Err(err.into()),
        };
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
                } else if mode == QPBaseQueueType::WorkerQueue {
                    let kv_key = format!("{}.{}", subject, hex::encode(job.get_restorable_job_id()));

                    self.kv
                        .put(&kv_key, Bytes::copy_from_slice(jet_msg.reply.as_deref().unwrap().as_bytes()))
                        .await?;
                }
            } else if mode == QPBaseQueueType::WorkerQueue {
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
        let has_expected_size = expected_size.is_some();
        let real_expected_size = expected_size.unwrap_or(0);

        let consumer = match self.get_consumer_cached(&durable_name).await {
            Ok(consumer) => consumer,
            Err(err) if Self::is_consumer_not_found_error(&err) => return Ok(0),
            Err(err) => return Err(err),
        };
        let mut messages = match consumer.fetch().max_messages(max_messages_per_batch).messages().await {
            Ok(messages) => messages,
            Err(err) if Self::is_consumer_not_found_error(&err) => {
                self.invalidate_consumer_cache(durable_name).await;
                return Ok(0);
            }
            Err(err) => return Err(err.into()),
        };
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
                } else if ack_mode == JetStreamAckMode::AckEach
                    || (ack_mode == JetStreamAckMode::AckBatchLast && total_messages_dumped >= max_messages_per_batch && max_messages_per_batch != 0)
                {
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

    pub async fn get_message_if_exists_dq_bytes_ephemeral(
        &self,
        subject: &str,
        durable_name: &str,
        ack_mode: JetStreamAckMode,
    ) -> anyhow::Result<Option<Vec<u8>>> {

        let consumer = match self.get_consumer_cached(durable_name).await {
            Ok(consumer) => consumer,
            Err(err) if Self::is_consumer_not_found_error(&err) => return Ok(None),
            Err(err) => return Err(err),
        };

        let request = consumer.fetch().max_messages(1);
        let mut messages = match request.messages().await {
            Ok(messages) => messages,
            Err(err) if Self::is_consumer_not_found_error(&err) => {
                self.invalidate_consumer_cache(durable_name).await;
                return Ok(None);
            }
            Err(err) => return Err(err.into()),
        };

        if let Some(Ok(jet_msg)) = messages.next().await {
            let job = jet_msg.payload.to_vec();
            if ack_mode == JetStreamAckMode::NoAck {
                return Ok(Some(job));
            } else {
                jet_msg.ack().await.map_err(|e| anyhow::anyhow!("Failed to ACK message: {}", e))?;
            }
            Ok(Some(job))
        } else {
            Ok(None)
        }
    }
    pub async fn get_message_if_exists_dq_bytes_ephemeral_qi<QueueItem: PCoreQueueItemBase>(
        &self,
        subject: &str,
        durable_name: &str,
        ack_mode: JetStreamAckMode,
    ) -> anyhow::Result<Option<QueueItem>> {

        let consumer = match self.get_consumer_cached(durable_name).await {
            Ok(consumer) => consumer,
            Err(err) if Self::is_consumer_not_found_error(&err) => return Ok(None),
            Err(err) => return Err(err),
        };

        let request = consumer.fetch().max_messages(1);
        let mut messages = match request.messages().await {
            Ok(messages) => messages,
            Err(err) if Self::is_consumer_not_found_error(&err) => {
                self.invalidate_consumer_cache(durable_name).await;
                return Ok(None);
            }
            Err(err) => return Err(err.into()),
        };

        if let Some(Ok(jet_msg)) = messages.next().await {
            let job = QueueItem::decode_queue_item_ref(jet_msg.payload.as_ref())?;
            if ack_mode == JetStreamAckMode::NoAck {
                return Ok(Some(job));
            } else {
                jet_msg.ack().await.map_err(|e| anyhow::anyhow!("Failed to ACK message: {}", e))?;
            }
            Ok(Some(job))
        } else {
            Ok(None)
        }
    }
    pub async fn get_message_if_exists_dqi_worker<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        subject: &str,
        durable_name: &str,
    ) -> anyhow::Result<Option<QK::QueueItem>> {
        let mut timer = DebugTimer::new("get_next_worker_queue_item_or_none");

        /*tracing::info!("Getting message for worker queue, subject: {}, durable_name: {}", subject, durable_name);*/
        let consumer = match self.get_consumer_cached(durable_name).await {
            Ok(consumer) => consumer,
            Err(err) if Self::is_consumer_not_found_error(&err) => return Ok(None),
            Err(err) => return Err(err),
        };
        timer.lap("get_consumer_from_stream");
        let request = consumer.fetch().max_messages(1);
        let mut messages = match request.messages().await {
            Ok(messages) => messages,
            Err(err) if Self::is_consumer_not_found_error(&err) => {
                self.invalidate_consumer_cache(durable_name).await;
                return Ok(None);
            }
            Err(err) => return Err(err.into()),
        };
        timer.lap("consumer.fetch.messages");

        let base_queue_type = queue_key.get_queue_type();
        if base_queue_type != QPBaseQueueType::WorkerQueue {
            return Err(anyhow::anyhow!("Invalid queue type for worker queue retrieval"));
        }

        if let Some(Ok(jet_msg)) = messages.next().await {
            timer.lap("messages.next()");
            let job = QK::QueueItem::decode_queue_item_ref(jet_msg.payload.as_ref())?;
            let kv_key = format!("{}.{}", subject, hex::encode(job.get_restorable_job_id()));
            /*tracing::info!(
                "Got job from worker queue, subject: {}, durable_name: {}, kv_key: {}",
                subject,
                durable_name,
                kv_key
            );*/

            self.kv
                .put(&kv_key, Bytes::copy_from_slice(jet_msg.reply.as_deref().unwrap().as_bytes()))
                .await?;

            timer.lap("kv.put");
            Ok(Some(job))
        } else {
            timer.lap("messages.next()");
            //tracing::info!("No messages in worker queue found, subject: {}, durable_name: {}", subject, durable_name);

            Ok(None)
        }
    }


    pub async fn report_message_completed_dq(&self, subject: &str, report_id: &[u8]) -> anyhow::Result<bool> {
        let kv_key = format!("{}.{}", subject, hex::encode(report_id));
        if let Some(reply_bytes) = self.kv.get(&kv_key).await? {
            let reply = String::from_utf8(reply_bytes.to_vec())?;
            println!(
                "Reporting job completed for subject: {}, report_id: {}, reply: {}",
                subject,
                hex::encode(report_id),
                reply
            );
            self.jetstream.publish(reply, Bytes::from_static(b"+ACK")).await?;
            self.kv.delete(&kv_key).await?;
            return Ok(true);
        } else {
            tracing::info!(
                "Unable to report job completed for subject: {}, report_id: {}, {}",
                subject,
                hex::encode(report_id),
                "not found in kv store"
            );

            return Ok(false);
        }
    }
    /*
    pub async fn report_message_completed_dq(&self, subject: &str, report_id: &[u8]) -> anyhow::Result<bool> {
        let kv_key = format!("{}.{}", subject, hex::encode(report_id));
        if let Some(reply_bytes) = self.kv.get(&kv_key).await? {
            let reply = String::from_utf8(reply_bytes.to_vec())?;
            println!(
                "Reporting job completed for subject: {}, report_id: {}, reply: {}",
                subject,
                hex::encode(report_id),
                reply
            );

            let a = self.jetstream.publish(reply.clone(), Bytes::from_static(b"+ACK"));
            let b = self.kv.delete(&kv_key);
            let (a,b) = tokio::join!(a, b);

            a.map_err(|e| anyhow::anyhow!("Failed to ACK message: {}", e))?;
            b.map_err(|e| anyhow::anyhow!("Failed to delete kv key: {}", e))?;



            return Ok(true);
        } else {
            tracing::info!(
                "Unable to report job completed for subject: {}, report_id: {}, {}",
                subject,
                hex::encode(report_id),
                "not found in kv store"
            );

            return Ok(false);
        }
    }*/

    pub async fn wait_until_all_jobs_complete_or_timeout_dq(
        &self,
        subject: &str,
        durable_name: &str,
        _queue_type: QPBaseQueueType,
        barrier: &NatsWorkerQueuePublishBarrier,
        timeout_ms: u64,
    ) -> anyhow::Result<()> {
        if barrier.is_empty() {
            tracing::debug!(subject, durable_name, "Empty worker publication barrier completed immediately");
            return Ok(());
        }

        let required_ack_stream_sequence = barrier
            .required_ack_stream_sequence()
            .expect("non-empty publication barrier must have a maximum stream sequence");
        tracing::info!(
            subject,
            durable_name,
            publish_min_stream_sequence = ?barrier.min_stream_sequence,
            publish_max_stream_sequence = required_ack_stream_sequence,
            job_count = barrier.message_count,
            "Waiting for worker publication barrier"
        );
        let start = Instant::now();
        let max_wait: Duration = Duration::from_millis(timeout_ms);

        loop {
            let mut consumer = match self.get_consumer_cached(&durable_name).await {
                Ok(c) => c,
                Err(e) if Self::is_consumer_not_found_error(&e) => {
                    self.invalidate_consumer_cache(durable_name).await;
                    return consumer_missing_with_barrier(subject, durable_name, barrier);
                }
                Err(e) => {
                    tracing::error!("Failed to get consumer: {}", e);
                    anyhow::bail!("Failed to get consumer for subject: {}, durable_name: {} {:?}", subject, durable_name,e );
                }
            };
            let info = match consumer.info().await {
                Ok(i) => i,
                Err(e) if Self::is_consumer_not_found_error(&e) => {
                    self.invalidate_consumer_cache(durable_name).await;
                    return consumer_missing_with_barrier(subject, durable_name, barrier);
                }
                Err(e) => {
                    tracing::error!("Failed to get consumer info: {}", e);
                    anyhow::bail!("Failed to get consumer info for subject: {}, durable_name: {} {:?}", subject, durable_name,e );
                }
            };
            if worker_queue_completion_reached(
                info.num_pending,
                info.num_ack_pending,
                info.delivered.stream_sequence,
                info.ack_floor.stream_sequence,
                required_ack_stream_sequence,
            ) {
                tracing::info!(
                    subject,
                    durable_name,
                    publish_max_stream_sequence = required_ack_stream_sequence,
                    consumer_delivered_stream_sequence = info.delivered.stream_sequence,
                    consumer_ack_floor_stream_sequence = info.ack_floor.stream_sequence,
                    num_pending = info.num_pending,
                    num_ack_pending = info.num_ack_pending,
                    elapsed_ms = start.elapsed().as_millis(),
                    "Worker publication barrier completed"
                );
                return Ok(());
            }else{
                tracing::trace!(
                    "still waiting... subject: {} consumer: {} pending: {}, ack_pending: {}, delivered_seq: {}, ack_floor_seq: {}",
                    subject,
                    durable_name,
                    info.num_pending,
                    info.num_ack_pending,
                    info.delivered.stream_sequence,
                    info.ack_floor.stream_sequence,
                );
            }
            if start.elapsed() > max_wait {
                return Err(anyhow::anyhow!("Timeout waiting for all jobs to complete"));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        consumer_missing_with_barrier, worker_queue_completion_reached,
        NatsWorkerQueuePublishBarrier,
    };

    fn barrier_with_sequences(sequences: &[u64]) -> NatsWorkerQueuePublishBarrier {
        let mut barrier = NatsWorkerQueuePublishBarrier::default();
        for sequence in sequences {
            barrier.record_ack(*sequence);
        }
        barrier
    }

    #[test]
    fn previous_idle_consumer_does_not_complete_current_publication() {
        assert!(!worker_queue_completion_reached(0, 0, 551, 551, 552));
    }

    #[test]
    fn delivered_to_barrier_without_ack_does_not_complete() {
        assert!(!worker_queue_completion_reached(0, 1, 552, 551, 552));
    }

    #[test]
    fn ack_floor_at_barrier_completes_transport_wait() {
        assert!(worker_queue_completion_reached(0, 0, 552, 552, 552));
    }

    #[test]
    fn pending_messages_keep_barrier_open() {
        assert!(!worker_queue_completion_reached(1, 0, 552, 552, 552));
    }

    #[test]
    fn consumer_missing_with_valid_barrier_is_an_error() {
        let barrier = barrier_with_sequences(&[552]);
        assert!(consumer_missing_with_barrier("jobs", "worker", &barrier).is_err());
    }

    #[test]
    fn publication_barrier_uses_maximum_publish_ack_sequence() {
        let barrier = barrier_with_sequences(&[553, 552, 555, 554]);
        assert_eq!(barrier.min_stream_sequence, Some(552));
        assert_eq!(barrier.max_stream_sequence, Some(555));
        assert_eq!(barrier.message_count, 4);
    }
}

#[async_trait]
impl QStandardQueueBase for NatsJetStreamClient {
    async fn ensure_stream(&self) -> anyhow::Result<()> {
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

    async fn ensure_consumer<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
    ) -> anyhow::Result<()> {
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let durable_name = queue_key.get_durable_name(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let queue_type = queue_key.get_queue_type();

        let cache_key = format!("{}:{}", self.stream_name, durable_name);

        if self.consumer_cache.get(&cache_key).await.is_some() {
            return Ok(());
        }

        let config = PullConfig {
            durable_name: Some(durable_name.to_string()),
            filter_subject: subject.to_string(),
            ..self.get_pull_config_for_queue_type(queue_type)
        };

        let consumer = self.jetstream.create_consumer_on_stream(config, &self.stream_name).await?;
        self.consumer_cache.insert(cache_key, consumer).await;
        Ok(())
    }

    async fn recreate_consumer<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
    ) -> anyhow::Result<()> {
        let durable_name = queue_key.get_durable_name(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let cache_key = format!("{}:{}", self.stream_name, durable_name);

        self.consumer_cache.invalidate(&cache_key).await;

        let stream = self.jetstream.get_stream(&self.stream_name).await?;
        if let Err(e) = stream.delete_consumer(&durable_name).await {
            let s = e.to_string().to_lowercase();
            if !s.contains("not found") && !s.contains("does not exist") {
                return Err(e.into());
            }
        }

        <Self as QStandardQueueBase>::ensure_consumer(self, queue_key, realm_id, realm_sub_id, unique_id, task_group).await
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
    ) -> anyhow::Result<()> {
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
        let mut total = self
            .dump_queue_dq_bytes_ephemeral(
                &subject,
                &durable_name,
                JetStreamAckMode::AckBatchLast,
                1000,
                max_items,
                None,
                &mut bytes_vec,
            )
            .await?;

        let mut total_dumped = total;
        while total != 0 && total_dumped < max_items {
            total = self
                .dump_queue_dq_bytes_ephemeral(
                    &subject,
                    &durable_name,
                    JetStreamAckMode::AckBatchLast,
                    1000,
                    max_items - total_dumped,
                    None,
                    &mut bytes_vec,
                )
                .await?;
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

        let consumer = match self.get_consumer_cached(&durable_name).await {
            Ok(consumer) => consumer,
            Err(err) if Self::is_consumer_not_found_error(&err) => return Ok(items),
            Err(err) => return Err(err),
        };
        while total_items_dumped < max_items {
            let mut messages = match consumer
                .fetch()
                .max_messages(real_batch_size.min(max_items - total_items_dumped))
                .messages()
                .await
            {
                Ok(messages) => messages,
                Err(err) if Self::is_consumer_not_found_error(&err) => {
                    self.invalidate_consumer_cache(&durable_name).await;
                    return Ok(items);
                }
                Err(err) => return Err(err.into()),
            };
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
        self.get_message_if_exists_dq_bytes_ephemeral(&subject, &durable_name, JetStreamAckMode::AckEach)
            .await
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

        self.get_message_if_exists_dq_bytes_ephemeral_qi(&subject, &durable_name, JetStreamAckMode::AckEach)
            .await
    }

    async fn delete_ephemeral_queue_consumer<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
    ) -> anyhow::Result<()> {
        self.delete_consumer_for_queue(queue_key, realm_id, realm_sub_id, unique_id, task_group)
            .await
    }

}

impl QStandardWorkerQueue for NatsJetStreamClient {
    type PublishBarrier = NatsWorkerQueuePublishBarrier;
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
    ) -> anyhow::Result<Self::PublishBarrier> {
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        self.publish_worker_payloads(
            &subject,
            vec![Bytes::from(item.encode_queue_item_vec()?)],
        )
        .await
    }
    async fn publish_many_worker_queue_items_ref<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items: &[&QK::QueueItem],
    ) -> anyhow::Result<Self::PublishBarrier> {
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let payloads = items
            .iter()
            .map(|item| item.encode_queue_item_vec().map(Bytes::from))
            .collect::<anyhow::Result<Vec<_>>>()?;
        self.publish_worker_payloads(&subject, payloads).await
    }
    async fn publish_worker_queue_item_owned<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        item: QK::QueueItem,
    ) -> anyhow::Result<Self::PublishBarrier> {
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        self.publish_worker_payloads(
            &subject,
            vec![Bytes::from(item.encode_queue_item_vec()?)],
        )
        .await
    }
    async fn publish_many_worker_queue_items_owned<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items: Vec<QK::QueueItem>,
    ) -> anyhow::Result<Self::PublishBarrier> {
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let payloads = items
            .iter()
            .map(|item| item.encode_queue_item_vec().map(Bytes::from))
            .collect::<anyhow::Result<Vec<_>>>()?;
        self.publish_worker_payloads(&subject, payloads).await
    }
    async fn publish_many_worker_queue_items<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_id: QCoreProcCheckpointUniqueId,
        task_group: u32,
        items: &[QK::QueueItem],
    ) -> anyhow::Result<Self::PublishBarrier> {
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let payloads = items
            .iter()
            .map(|item| item.encode_queue_item_vec().map(Bytes::from))
            .collect::<anyhow::Result<Vec<_>>>()?;
        self.publish_worker_payloads(&subject, payloads).await
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
    ) -> anyhow::Result<Option<QK::QueueItem>> {
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let durable_name = queue_key.get_durable_name(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let start_time = Instant::now();
        let timeout_duration = Duration::from_millis(timeout_ms);
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Some(msg) = self
                        .get_message_if_exists_dqi_worker(queue_key, &subject, &durable_name)
                        .await?
                    {
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
    ) -> anyhow::Result<Vec<QK::QueueItem>> {
        if max_items == 0 {
            return Ok(Vec::new());
        }
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let durable_name = queue_key.get_durable_name(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let size_hint = QK::QueueItem::get_size_hint();
        let has_fixed_size = QK::QueueItem::has_fixed_size() && size_hint > 0;

        let consumer = match self.get_consumer_cached(&durable_name).await {
            Ok(consumer) => consumer,
            Err(err) if Self::is_consumer_not_found_error(&err) => return Ok(Vec::new()),
            Err(err) => return Err(err),
        };
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
            let mut messages = match consumer.fetch().max_messages(max_messages_per_batch.min(max_items)).messages().await {
                Ok(messages) => messages,
                Err(err) if Self::is_consumer_not_found_error(&err) => {
                    self.invalidate_consumer_cache(&durable_name).await;
                    return Ok(data_vec);
                }
                Err(err) => return Err(err.into()),
            };
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
                } else {
                    tracing::error!("failed to get a reply/ack for a worker queue job, ignoring");
                    total_messages_dumped -= 1;
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
    ) -> anyhow::Result<Option<QK::QueueItem>> {
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        let durable_name = queue_key.get_durable_name(&self.base_namespace, realm_id, realm_sub_id, unique_id, task_group);
        //println!("Getting next worker queue item for subject: {}, durable_name: {}", subject, durable_name);
        self.get_message_if_exists_dqi_worker(queue_key, &subject, &durable_name).await
    }
    async fn wait_until_all_jobs_complete_or_timeout_worker<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_topic: u128,
        task_group: u32,
        barrier: &Self::PublishBarrier,
        timeout_ms: u64,
    ) -> anyhow::Result<()> {
        let subject = queue_key.get_queue_subject(&self.base_namespace, realm_id, realm_sub_id, unique_topic, task_group);
        let durable_name = queue_key.get_durable_name(&self.base_namespace, realm_id, realm_sub_id, unique_topic, task_group);
        self.wait_until_all_jobs_complete_or_timeout_dq(&subject, &durable_name, queue_key.get_queue_type(), barrier, timeout_ms)
            .await
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

    async fn delete_worker_queue_consumer<QK: PCoreStandardQueueKeyForRealm>(
        &self,
        queue_key: &QK,
        realm_id: u64,
        realm_sub_id: u64,
        unique_topic: u128,
        task_group: u32,
    ) -> anyhow::Result<()> {
        self.delete_consumer_for_queue(queue_key, realm_id, realm_sub_id, unique_topic, task_group)
            .await
    }
}
