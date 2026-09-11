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

#[cfg(test)]
mod tests {
    use parth_core::felt::FromPrimitiveValuesFelt;

    use super::*;
    use crate::proof_input::guta::end_cap_input::PsyUserEventRecord;
    use crate::v1::qdata::bloom_filter::BloomConfig;

    type F = parth_core::PF;

    #[derive(Clone)]
    struct TestEvent {
        user: u64,
        contract: u64,
        action: u64,
    }

    impl EventBloomItem for TestEvent {
        fn user_id(&self) -> u64 {
            self.user
        }

        fn contract_id(&self) -> u64 {
            self.contract
        }

        fn action(&self) -> u64 {
            self.action
        }
    }

    fn event() -> TestEvent {
        TestEvent { user: 11, contract: 22, action: 33 }
    }

    fn record(user: u64, contract: u64, action: u64) -> PsyUserEventRecord<F> {
        PsyUserEventRecord {
            checkpoint_id: F::from_u64_value(1),
            user_id: F::from_u64_value(user),
            contract_id: F::from_u64_value(contract),
            method_id: F::from_u64_value(action),
            event_index: F::from_u64_value(2),
            data: vec![],
        }
    }

    #[test]
    fn derived_keys_use_little_endian_field_concatenation() {
        let e = event();
        assert_eq!(e.action_key(), 33u64.to_le_bytes().to_vec());
        assert_eq!(e.contract_key(), 22u64.to_le_bytes().to_vec());
        assert_eq!(e.user_key(), 11u64.to_le_bytes().to_vec());
        assert_eq!(
            e.contract_action_key(),
            [22u64.to_le_bytes(), 33u64.to_le_bytes()].concat()
        );
        assert_eq!(
            e.user_contract_key(),
            [11u64.to_le_bytes(), 22u64.to_le_bytes()].concat()
        );
        assert_eq!(
            e.user_contract_action_key(),
            [11u64.to_le_bytes(), 22u64.to_le_bytes(), 33u64.to_le_bytes()].concat()
        );

        // All keys is exactly the six index strategies, in order.
        assert_eq!(
            e.all_keys(),
            vec![
                e.action_key(),
                e.contract_key(),
                e.user_key(),
                e.contract_action_key(),
                e.user_contract_key(),
                e.user_contract_action_key(),
            ]
        );
    }

    #[test]
    fn reference_impls_forward_to_the_underlying_event() {
        let e = event();
        let by_ref = &e;
        assert_eq!(by_ref.user_id(), 11);
        assert_eq!(by_ref.contract_id(), 22);
        assert_eq!(by_ref.action(), 33);

        let mut mutable = e;
        let by_mut = &mut mutable;
        assert_eq!(by_mut.user_id(), 11);
        assert_eq!(by_mut.contract_id(), 22);
        assert_eq!(by_mut.action(), 33);
    }

    #[test]
    fn insert_all_keys_into_makes_every_key_queryable() {
        let mut filter = QPBloomFilter::new(BloomConfig::new(100, 0.001));
        event().insert_all_keys_into(&mut filter);
        for key in event().all_keys() {
            assert!(filter.contains(&key), "Key {:?} should be queryable", key);
        }
    }

    #[test]
    fn event_filter_adds_single_and_multiple_events() {
        let mut filter = QPBloomFilter::new(BloomConfig::new(100, 0.001));
        filter.add_event(&event());
        for key in event().all_keys() {
            assert!(filter.contains(&key));
        }

        let events = vec![
            event(),
            TestEvent { user: 44, contract: 55, action: 66 },
        ];
        let mut owned_filter = QPBloomFilter::new(BloomConfig::new(100, 0.001));
        owned_filter.add_events(events.iter());
        let mut mutable_events = events.clone();
        let mut mut_filter = QPBloomFilter::new(BloomConfig::new(100, 0.001));
        mut_filter.add_events(mutable_events.iter_mut());

        for e in events.iter() {
            for key in e.all_keys() {
                assert!(owned_filter.contains(&key), "Owned-iterator filter should contain {:?}", key);
                assert!(mut_filter.contains(&key), "Mut-iterator filter should contain {:?}", key);
            }
        }
    }

    #[test]
    fn user_event_record_keys_read_canonical_field_values() {
        let e = record(7, 8, 9);
        assert_eq!(e.user_id(), 7);
        assert_eq!(e.contract_id(), 8);
        assert_eq!(e.action(), 9);
        assert_eq!(e.user_key(), 7u64.to_le_bytes().to_vec());
        assert_eq!(e.contract_key(), 8u64.to_le_bytes().to_vec());
        assert_eq!(e.action_key(), 9u64.to_le_bytes().to_vec());
    }
}
