use async_trait::async_trait;

#[async_trait]
pub trait NMQBasicSubscriber {
    async fn dequeue_message_from_queue(&self, realm_id: u64, queue_type: u16, channel_id: u128, variant: u64) -> anyhow::Result<Vec<u8>>;
    async fn dump_messages_from_queue(&self, realm_id: u64, queue_type: u16, channel_id: u128, variant: u64) -> anyhow::Result<Vec<Vec<u8>>>;
}


#[async_trait]
pub trait NMQQueueWaiter {
    async fn wait_for_message_in_queue(&self, realm_id: u64, queue_type: u16, channel_id: u128, variant: u64, timeout_ms: u64) -> anyhow::Result<Vec<u8>>;
}
pub trait NMQSubscriber: NMQBasicSubscriber + NMQQueueWaiter {

}
impl<T: NMQBasicSubscriber + NMQQueueWaiter> NMQSubscriber for T {}


#[async_trait]
pub trait NMQPublisher {
    async fn enqueue_message_to_queue(&self, realm_id: u64, queue_type: u16, channel_id: u128, variant: u64, message: Vec<u8>) -> anyhow::Result<()>;
    async fn enqueue_messages_to_queue(&self, realm_id: u64, queue_type: u16, channel_id: u128, variant: u64, message: Vec<Vec<u8>>) -> anyhow::Result<()>;
}

pub trait NMQMessageQueue: NMQSubscriber + NMQPublisher {}
impl<T: NMQSubscriber + NMQPublisher> NMQMessageQueue for T {}