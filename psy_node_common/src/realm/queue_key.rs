use parth_core::data::queue::queue_key::QPStandardUniqueIdQueueKey;
use psy_data::{queue_items::realm_user_update::PsyRealmUserUpdatQueueItem, worker::metadata_with_job_id::PsyProvingJobMetadataWithJobId};

use crate::constants::queue::{PQ_COORDINATOR_PROVING_WORK_QUEUE_TOPIC_ID, PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID};

pub type RealmUserUpdateQueueKey<F, Hash> =
    QPStandardUniqueIdQueueKey<PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID, PsyRealmUserUpdatQueueItem<F, Hash>>;




pub type RealmProvingWorkQueueKey<Hash, JobId> =
    QPStandardUniqueIdQueueKey<PQ_COORDINATOR_PROVING_WORK_QUEUE_TOPIC_ID, PsyProvingJobMetadataWithJobId<Hash, JobId>>;