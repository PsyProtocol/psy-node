use std::sync::Arc;

use crate::jobhq::nats::core::NatsJetStreamClient;


#[derive(Clone)]
pub struct NatsJetStreamClientForRealm {
    pub client: Arc<NatsJetStreamClient>,
    pub realm_id: u64,
    pub realm_sub_id: u64,

    realm_subject_prefix: String,
    realm_stream_name: String,
    realm_kv_bucket_name: String,
}

impl NatsJetStreamClientForRealm {
    pub fn new(client: Arc<NatsJetStreamClient>, realm_id: u64, realm_sub_id: u64) -> Self {
        Self {
            client,
            realm_id,
            realm_sub_id,
            realm_subject_prefix: format!("R.{}.{}", realm_id, realm_sub_id),
            realm_stream_name: format!("R_{}_{}", realm_id, realm_sub_id),
            realm_kv_bucket_name: format!("R_{}_{}_KV", realm_id, realm_sub_id),
        }
    }

    pub fn get_realm_subject_prefix(&self) -> String {
        format!("R.{}.{}", self.realm_id, self.realm_sub_id)
    }

    pub fn get_realm_stream_name(&self) -> String {
        format!("R_{}_{}", self.realm_id, self.realm_sub_id)
    }

    pub fn get_realm_kv_bucket_name(&self) -> String {
        format!("R_{}_{}_KV", self.realm_id, self.realm_sub_id)
    }
}