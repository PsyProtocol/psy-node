use parth_core::data::queue::queue_key::QPStandardUniqueIdQueueKey;
use psy_core::job::job_id::QProvingJobDataID;

use crate::constants::queue::PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID;

pub type RealmUserUpdateQueueKey =
    QPStandardUniqueIdQueueKey<PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID, QProvingJobDataID>;


