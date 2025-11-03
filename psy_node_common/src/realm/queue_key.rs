use parth_core::data::queue::queue_key::QPStandardUniqueIdQueueKey;
use psy_data::queue_items::realm_user_update::PsyRealmUserUpdatQueueItem;

use crate::constants::queue::PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID;

pub type RealmUserUpdateQueueKey<F, Hash> =
    QPStandardUniqueIdQueueKey<PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID, PsyRealmUserUpdatQueueItem<F, Hash>>;


