use parth_core::data::queue::queue_key::QPStandardUniqueIdQueueKey;
use psy_data::{guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobID, v1::qdata::{contract::PsyDeployContractQueueItem, public_key::PZKPublicKeyInfo}, worker::metadata_with_job_id::PsyProvingJobMetadataWithJobId};

use crate::constants::queue::{PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID, PQ_COORDINATOR_REGISTER_USER_PUBLIC_KEY_QUEUE_TOPIC_ID, PQ_COORDINATOR_SUBMIT_REALM_GUTA_UPDATE_QUEUE_TOPIC_ID, PQ_REALM_PROVING_WORK_QUEUE_TOPIC_ID};

pub type CoordinatorRegisterUserPublicKeyQueueKey<Hash> =
    QPStandardUniqueIdQueueKey<PQ_COORDINATOR_REGISTER_USER_PUBLIC_KEY_QUEUE_TOPIC_ID, PZKPublicKeyInfo<Hash>>;

pub type CoordinatorDeployContractQueueKey<F, Hash> =
    QPStandardUniqueIdQueueKey<PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID, PsyDeployContractQueueItem<F, Hash>>;


pub type CoordinatorSubmitRealmGUTAUpdateQueueKey<F, Hash> =
    QPStandardUniqueIdQueueKey<PQ_COORDINATOR_SUBMIT_REALM_GUTA_UPDATE_QUEUE_TOPIC_ID, GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<F, Hash>>;


pub type CoordinatorProvingWorkQueueKey<Hash, JobId> =
    QPStandardUniqueIdQueueKey<PQ_REALM_PROVING_WORK_QUEUE_TOPIC_ID, PsyProvingJobMetadataWithJobId<Hash, JobId>>;