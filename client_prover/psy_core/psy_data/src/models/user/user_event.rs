use kvq::traits::{KVQStoreAdapter, KVQStoreAdapterReader};
use plonky2::hash::hash_types::RichField;

use crate::{dpn::event::PsyUserEventRecord, models::kvq_merkle::model::CHECKPOINT_ID_FUZZY_SIZE, qdata::event_key::EventTableIdKey};

pub trait UserEventModelReaderCore<
    const USER_EVENT_TABLE_TYPE: u16,
    S,
    F: RichField,
    IDKVA: KVQStoreAdapterReader<S, EventTableIdKey<USER_EVENT_TABLE_TYPE>, PsyUserEventRecord<F>>,
>
{
    fn get_event_by_index(store: &S, checkpoint_id: u64, user_id: u64, event_index: u64) -> anyhow::Result<PsyUserEventRecord<F>> {
        tracing::debug!("UserEventModelCore::get_event_by_index: {} {} {}", checkpoint_id, user_id, event_index);
        IDKVA::get_leq(
            store,
            &EventTableIdKey::new(checkpoint_id, user_id, event_index),
            CHECKPOINT_ID_FUZZY_SIZE,
        )?
        .ok_or_else(|| anyhow::anyhow!("Event not found"))
    }
    fn get_events_by_index(store: &S, checkpoint_id: u64, user_id: u64, event_indexes: &[u64]) -> anyhow::Result<Vec<PsyUserEventRecord<F>>> {
        tracing::debug!(
            "UserEventModelCore::get_events_by_index: {} {} {:?}",
            checkpoint_id,
            user_id,
            event_indexes
        );
        let keys = event_indexes
            .iter()
            .map(|id| EventTableIdKey::new(checkpoint_id, user_id, *id))
            .collect::<Vec<_>>();
        IDKVA::get_many_leq_u(store, &keys, CHECKPOINT_ID_FUZZY_SIZE)
    }
}

pub trait UserEventModelCore<
    const USER_EVENT_TABLE_TYPE: u16,
    S,
    F: RichField,
    IDKVA: KVQStoreAdapter<S, EventTableIdKey<USER_EVENT_TABLE_TYPE>, PsyUserEventRecord<F>>,
>: UserEventModelReaderCore<USER_EVENT_TABLE_TYPE, S, F, IDKVA>
{
    fn set_event(store: &S, checkpoint_id: u64, user_id: u64, event_index: u64, event: PsyUserEventRecord<F>) -> anyhow::Result<()> {
        let key_id = EventTableIdKey::new(checkpoint_id, user_id, event_index);
        tracing::debug!("UserEventModelCore::set_event: {} {} {}", checkpoint_id, user_id, event_index);
        IDKVA::set(store, key_id, event)?;
        Ok(())
    }
    fn set_event_ref(store: &S, checkpoint_id: u64, user_id: u64, event_index: u64, event: &PsyUserEventRecord<F>) -> anyhow::Result<()> {
        let key_id = EventTableIdKey::new(checkpoint_id, user_id, event_index);
        tracing::debug!("UserEventModelCore::set_event_ref: {} {} {}", checkpoint_id, user_id, event_index);
        IDKVA::set_ref(store, &key_id, event)?;
        Ok(())
    }
    fn set_events(store: &S, checkpoint_id: u64, user_id: u64, events: &[PsyUserEventRecord<F>]) -> anyhow::Result<()> {
        let key_ids = events
            .iter()
            .enumerate()
            .map(|(i, _u)| EventTableIdKey::new(checkpoint_id, user_id, i as u64))
            .collect::<Vec<_>>();
        tracing::debug!("UserEventModelCore::set_events: {} {} {:?}", checkpoint_id, user_id, events);
        IDKVA::set_many_split_ref(store, &key_ids, events)?;
        Ok(())
    }
}

pub struct UserEventModel<const USER_EVENT_TABLE_TYPE: u16, S, F: RichField, IDKVA> {
    _idkva: IDKVA,
    _store: S,
    _phantom: std::marker::PhantomData<F>,
}

impl<
        const USER_EVENT_TABLE_TYPE: u16,
        S,
        F: RichField,
        IDKVA: KVQStoreAdapterReader<S, EventTableIdKey<USER_EVENT_TABLE_TYPE>, PsyUserEventRecord<F>>,
    > UserEventModelReaderCore<USER_EVENT_TABLE_TYPE, S, F, IDKVA> for UserEventModel<USER_EVENT_TABLE_TYPE, S, F, IDKVA>
{
}
impl<const USER_EVENT_TABLE_TYPE: u16, S, F: RichField, IDKVA: KVQStoreAdapter<S, EventTableIdKey<USER_EVENT_TABLE_TYPE>, PsyUserEventRecord<F>>>
    UserEventModelCore<USER_EVENT_TABLE_TYPE, S, F, IDKVA> for UserEventModel<USER_EVENT_TABLE_TYPE, S, F, IDKVA>
{
}
