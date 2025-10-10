use crate::{data::fixed_serializable::QPDFixedSizeSerializable, QCoreProcCheckpointUniqueId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum QPBaseQueueType {
    StandardEphemeral = 0,
    WorkerQueue = 1,
}

pub trait PCoreSubjectQueueBase {
    fn get_queue_subject(&self, core_namespace: &str, realm_id: u64, realm_sub_id: u64, unique_id: QCoreProcCheckpointUniqueId, task_group: u32) -> String;
    fn get_durable_name(&self, core_namespace: &str, realm_id: u64, realm_sub_id: u64, unique_id: QCoreProcCheckpointUniqueId, task_group: u32) -> String;
    fn get_queue_type(&self) -> QPBaseQueueType;
}
pub trait PCoreQueueItemBase: Sized + Clone + Send + Sync {
    fn is_queue_item(data: &[u8]) -> bool;
    fn decode_queue_item_ref(data: &[u8]) -> anyhow::Result<Self>;
    fn encode_queue_item_vec(&self) -> anyhow::Result<Vec<u8>>;
    fn get_restorable_job_id(&self) -> Vec<u8>;
    fn get_size_hint() -> usize;
    fn has_fixed_size() -> bool;
}


pub trait PCoreStandardQueueKeyForRealm: PCoreSubjectQueueBase + Send + Sync + Clone {
    type QueueItem: PCoreQueueItemBase + Clone + Send + Sync;

}



pub trait PCoreQueueKeySized<const N: usize, QueueItem: QPDFixedSizeSerializable<N>> {
    fn is_queue_item_sized(data: &[u8]) -> bool;
    fn decode_queue_item_sized_ref(data: &[u8]) -> anyhow::Result<QueueItem>;
    fn encode_queue_item_sized_bytes(item: &QueueItem) -> anyhow::Result<[u8; N]>;
}
#[derive(Debug, Clone, Copy)]
pub struct QPStandardUniqueIdQueueKeyOld<const QUEUE_TOPIC_ID: u32>{
    pub realm_id: u64,
    pub realm_sub_id: u64,
    pub unique_id: QCoreProcCheckpointUniqueId,
    pub task_group: u64,
    pub queue_type: QPBaseQueueType,
}

impl<const QUEUE_TOPIC_ID: u32> PCoreSubjectQueueBase for QPStandardUniqueIdQueueKeyOld<QUEUE_TOPIC_ID> {
    fn get_queue_subject(&self, core_namespace: &str, realm_id: u64, realm_sub_id: u64, unique_id: QCoreProcCheckpointUniqueId, task_group: u32) -> String {
        format!(
            "{}.pq.r{:x}.rs{:x}.u{:x}.qt{:x}.g{:x}",
            core_namespace, realm_id, realm_sub_id, unique_id, QUEUE_TOPIC_ID, task_group
        )
    }
    fn get_durable_name(&self, core_namespace: &str, realm_id: u64, realm_sub_id: u64, unique_id: QCoreProcCheckpointUniqueId, task_group: u32) -> String {
        format!(
            "{}_pq_r{:x}_rs{:x}_u{:x}_qt{:x}_g{:x}",
            core_namespace, realm_id, realm_sub_id, unique_id, QUEUE_TOPIC_ID, task_group
        )
    }
    fn get_queue_type(&self) -> QPBaseQueueType {
        self.queue_type
    }
}

#[derive(Debug, Clone, Copy)]
pub struct QPStandardUniqueIdQueueKey<const QUEUE_TOPIC_ID: u32, QueueItem: PCoreQueueItemBase>{
    pub realm_id: u64,
    pub realm_sub_id: u64,
    pub unique_id: QCoreProcCheckpointUniqueId,
    pub task_group: u64,
    pub queue_type: QPBaseQueueType,
    pub _phantom_queue_item: std::marker::PhantomData<QueueItem>,
}

impl<const QUEUE_TOPIC_ID: u32, QueueItem: PCoreQueueItemBase> PCoreSubjectQueueBase for QPStandardUniqueIdQueueKey<QUEUE_TOPIC_ID, QueueItem> {
    fn get_queue_subject(&self, core_namespace: &str, realm_id: u64, realm_sub_id: u64, unique_id: QCoreProcCheckpointUniqueId, task_group: u32) -> String {
        format!(
            "{}.pq.r{:x}.rs{:x}.u{:x}.qt{:x}.g{:x}",
            core_namespace, realm_id, realm_sub_id, unique_id, QUEUE_TOPIC_ID, task_group
        )
    }
    fn get_durable_name(&self, core_namespace: &str, realm_id: u64, realm_sub_id: u64, unique_id: QCoreProcCheckpointUniqueId, task_group: u32) -> String {
        format!(
            "{}_pq_r{:x}_rs{:x}_u{:x}_qt{:x}_g{:x}",
            core_namespace, realm_id, realm_sub_id, unique_id, QUEUE_TOPIC_ID, task_group
        )
    }
    fn get_queue_type(&self) -> QPBaseQueueType {
        self.queue_type
    }
}
impl<const QUEUE_TOPIC_ID: u32, QueueItem: PCoreQueueItemBase + Clone + Send + Sync> PCoreStandardQueueKeyForRealm for QPStandardUniqueIdQueueKey<QUEUE_TOPIC_ID, QueueItem> {
    type QueueItem = QueueItem;
}
