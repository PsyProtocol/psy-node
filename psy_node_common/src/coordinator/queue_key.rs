use parth_core::data::queue::queue_key::QPStandardUniqueIdQueueKey;
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::v1::qdata::public_key::PZKPublicKeyInfo;

use crate::constants::queue::{PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID, PQ_COORDINATOR_REGISTER_USER_PUBLIC_KEY_QUEUE_TOPIC_ID, PQ_COORDINATOR_SUBMIT_REALM_GUTA_UPDATE_QUEUE_TOPIC_ID};

pub type CoordinatorRegisterUserPublicKeyQueueKey<Hash> =
    QPStandardUniqueIdQueueKey<PQ_COORDINATOR_REGISTER_USER_PUBLIC_KEY_QUEUE_TOPIC_ID, PZKPublicKeyInfo<Hash>>;

pub type CoordinatorDeployContractQueueKey<Hash> =
    QPStandardUniqueIdQueueKey<PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID, PZKPublicKeyInfo<Hash>>;


pub type CoordinatorSubmitRealmGUTAUpdateQueueKey =
    QPStandardUniqueIdQueueKey<PQ_COORDINATOR_SUBMIT_REALM_GUTA_UPDATE_QUEUE_TOPIC_ID, QProvingJobDataID>;


