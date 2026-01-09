use parth_core::felt::QFelt64;

use super::QPBloomFilter;
use crate::proof_input::guta::end_cap_input::PsyUserEventRecord;

/// Trait for items that can be inserted into event bloom filters.
/// Provides key generation methods for various indexing strategies.
pub trait EventBloomItem {
    fn user_id(&self) -> u64;
    fn contract_id(&self) -> u64;
    fn action(&self) -> u64;

    /// Action key: 8 bytes (method_id)
    #[inline]
    fn action_key(&self) -> Vec<u8> {
        self.action().to_le_bytes().to_vec()
    }

    /// Contract key: 8 bytes (contract_address)
    #[inline]
    fn contract_key(&self) -> Vec<u8> {
        self.contract_id().to_le_bytes().to_vec()
    }

    /// User key: 8 bytes (user_address)
    #[inline]
    fn user_key(&self) -> Vec<u8> {
        self.user_id().to_le_bytes().to_vec()
    }

    /// Contract + Action key: 16 bytes
    #[inline]
    fn contract_action_key(&self) -> Vec<u8> {
        [self.contract_id().to_le_bytes(), self.action().to_le_bytes()].concat()
    }

    /// User + Contract key: 16 bytes
    #[inline]
    fn user_contract_key(&self) -> Vec<u8> {
        [self.user_id().to_le_bytes(), self.contract_id().to_le_bytes()].concat()
    }

    /// User + Contract + Action key: 24 bytes
    #[inline]
    fn user_contract_action_key(&self) -> Vec<u8> {
        [
            self.user_id().to_le_bytes(),
            self.contract_id().to_le_bytes(),
            self.action().to_le_bytes(),
        ]
        .concat()
    }

    /// Get all possible keys for this event (for batch insertion)
    #[inline]
    fn all_keys(&self) -> Vec<Vec<u8>> {
        vec![
            self.action_key(),
            self.contract_key(),
            self.user_key(),
            self.contract_action_key(),
            self.user_contract_key(),
            self.user_contract_action_key(),
        ]
    }

    /// Insert all keys into a bloom filter
    #[inline]
    fn insert_all_keys_into(&self, filter: &mut QPBloomFilter) {
        filter.insert_many(self.all_keys());
    }
}

impl<T: EventBloomItem> EventBloomItem for &T {
    #[inline]
    fn user_id(&self) -> u64 {
        (**self).user_id()
    }
    #[inline]
    fn contract_id(&self) -> u64 {
        (**self).contract_id()
    }
    #[inline]
    fn action(&self) -> u64 {
        (**self).action()
    }
}

impl<T: EventBloomItem> EventBloomItem for &mut T {
    #[inline]
    fn user_id(&self) -> u64 {
        (**self).user_id()
    }
    #[inline]
    fn contract_id(&self) -> u64 {
        (**self).contract_id()
    }
    #[inline]
    fn action(&self) -> u64 {
        (**self).action()
    }
}

/// Trait for bloom filters that can store events.
/// Provides methods to add events by inserting all their keys.
pub trait EventFilter {
    /// Add a single event to the filter.
    fn add_event<T: EventBloomItem>(&mut self, event: &T);

    /// Add multiple events to the filter.
    fn add_events<T: EventBloomItem, I>(&mut self, events: I)
    where
        I: IntoIterator<Item = T>;
}

impl EventFilter for QPBloomFilter {
    #[inline]
    fn add_event<T: EventBloomItem>(&mut self, event: &T) {
        self.insert_many(event.all_keys());
    }

    #[inline]
    fn add_events<T: EventBloomItem, I>(&mut self, events: I)
    where
        I: IntoIterator<Item = T>,
    {
        for event in events.into_iter() {
            self.add_event(&event);
        }
    }
}

impl<F: QFelt64> EventBloomItem for PsyUserEventRecord<F> {
    #[inline]
    fn user_id(&self) -> u64 {
        self.user_id.tuv_to_canonical_u64()
    }

    #[inline]
    fn contract_id(&self) -> u64 {
        self.contract_id.tuv_to_canonical_u64()
    }

    #[inline]
    fn action(&self) -> u64 {
        self.method_id.tuv_to_canonical_u64()
    }
}
