use fastbloom_rs::{BloomFilter as FastBloomFilter, FilterBuilder, Membership};
use serde::{Deserialize, Serialize};

/// Configuration for Bloom filter
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct BloomConfig {
    /// Target number of elements
    pub capacity: usize,
    /// Desired false positive rate (e.g., 0.001 for 0.1%)
    pub false_positive_rate: f64,
}

impl BloomConfig {
    /// Create a new config with given capacity and false positive rate
    pub fn new(capacity: usize, false_positive_rate: f64) -> Self {
        Self {
            capacity,
            false_positive_rate,
        }
    }

    /// Calculate optimal number of hash functions
    #[inline]
    pub fn num_hashes(&self) -> usize {
        let optimal = (-self.false_positive_rate.ln()) / std::f64::consts::LN_2;
        optimal.clamp(1.0, 32.0) as usize
    }

    /// Calculate required number of bits
    #[inline]
    pub fn num_bits(&self) -> usize {
        let optimal = self.capacity as f64 * (-self.false_positive_rate.ln()) / (std::f64::consts::LN_2).powi(2);
        optimal.ceil() as usize
    }

    /// Calculate the size in bytes needed to store the bits
    #[inline]
    pub fn num_bytes(&self) -> usize {
        (self.num_bits() + 7) / 8
    }
}

impl Default for BloomConfig {
    fn default() -> Self {
        Self {
            capacity: 1024,
            false_positive_rate: 0.001,
        }
    }
}

/// A Bloom filter wrapper using fastbloom-rs.
///
/// Provides a lightweight, serializable interface to the fastbloom
/// implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QPBloomFilter {
    inner: FastBloomFilter,
    config: BloomConfig,
}

impl QPBloomFilter {
    /// Create a new Bloom filter with given configuration
    #[inline]
    pub fn new(config: BloomConfig) -> Self {
        let inner = FilterBuilder::new(config.num_bits() as u64, config.false_positive_rate).build_bloom_filter();
        Self { inner, config }
    }

    /// Get the configuration
    #[inline]
    pub fn config(&self) -> BloomConfig {
        self.config
    }

    /// Add a single item to the filter
    #[inline]
    pub fn insert<T: AsRef<[u8]>>(&mut self, item: &T) {
        self.inner.add(item.as_ref());
    }

    /// Check if an item might be in the set
    #[inline]
    pub fn contains<T: AsRef<[u8]>>(&self, item: &T) -> bool {
        self.inner.contains(item.as_ref())
    }

    /// Add multiple items
    #[inline]
    pub fn insert_many<T: AsRef<[u8]>, I: IntoIterator<Item = T>>(&mut self, items: I) {
        for item in items {
            self.insert(&item);
        }
    }

    /// Get the size in bytes
    #[inline]
    pub fn size_bytes(&self) -> usize {
        0 // fastbloom-rs doesn't expose size directly
    }

    /// Get the underlying fastbloom filter (for advanced use)
    #[inline]
    pub fn inner(&self) -> &FastBloomFilter {
        &self.inner
    }

    /// Get mutable reference to underlying filter
    #[inline]
    pub fn inner_mut(&mut self) -> &mut FastBloomFilter {
        &mut self.inner
    }

    /// Merge another bloom filter into this one
    ///
    /// Both filters must have the same configuration (capacity, false positive
    /// rate). The merge operation is a bitwise OR of the underlying bit
    /// arrays.
    pub fn merge(&mut self, other: &QPBloomFilter) -> anyhow::Result<()> {
        // Check config equality
        if self.config != other.config {
            anyhow::bail!("Cannot merge bloom filters with different configurations");
        }

        // fastbloom-rs doesn't expose bit arrays directly, so we need to serialize and
        // merge
        let self_bytes = self.to_bytes()?;
        let other_bytes = other.to_bytes()?;

        let self_bits: &[u8] = &self_bytes;
        let other_bits: &[u8] = &other_bytes;

        // Merge by modifying the inner filter through serialization
        // This is a workaround since fastbloom-rs doesn't expose bit-level access
        // We deserialize into mutable bytes, OR them, and re-serialize
        let mut self_bytes_mut = self_bytes;
        for (a, b) in self_bytes_mut.iter_mut().zip(other_bits.iter()) {
            *a |= *b;
        }

        // Re-parse to update inner
        let merged: QPBloomFilter = Self::from_bytes(&self_bytes_mut)?;
        self.inner = merged.inner;
        Ok(())
    }

    /// Serialize to bytes using bincode
    #[inline]
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(Into::into)
    }

    /// Deserialize from bytes
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use parth_core::utils::QPGenRandom;

    use super::*;
    use crate::proof_input::guta::end_cap_input::PsyUserEventRecord;

    type F = parth_core::PF;

    const CAPACITY: usize = 1000;
    const FALSE_POSITIVE_RATE: f64 = 0.001;

    #[test]
    fn test_bloom_filter_insert_and_contains() -> anyhow::Result<()> {
        let config = BloomConfig::new(CAPACITY, FALSE_POSITIVE_RATE);
        let mut filter = QPBloomFilter::new(config);

        let items: Vec<&[u8]> = vec![b"hello", b"world", b"test", b"bloom", b"filter"];

        for item in &items {
            filter.insert(item);
        }

        // All inserted items should be found
        for item in &items {
            assert!(filter.contains(item), "Should find inserted item: {:?}", item);
        }

        // Non-inserted items should not be found (with high probability)
        assert!(!filter.contains(b"not inserted"));
        assert!(!filter.contains(b"another"));
        Ok(())
    }

    #[test]
    fn test_bloom_filter_insert_many() -> anyhow::Result<()> {
        let config = BloomConfig::new(CAPACITY, FALSE_POSITIVE_RATE);
        let mut filter = QPBloomFilter::new(config);

        let items: Vec<Vec<u8>> = (0..100).map(|i| format!("item_{}", i).into_bytes()).collect();

        filter.insert_many(&items);

        for item in &items {
            assert!(filter.contains(item), "Should find inserted item: {:?}", item);
        }
        Ok(())
    }

    #[test]
    fn test_bloom_filter_with_different_types() -> anyhow::Result<()> {
        let config = BloomConfig::new(CAPACITY, FALSE_POSITIVE_RATE);
        let mut filter = QPBloomFilter::new(config);

        // Test with various types
        filter.insert(&b"string bytes".to_vec());
        filter.insert(b"static bytes");
        filter.insert(&42u64.to_le_bytes());
        filter.insert(&[1u8, 2, 3, 4, 5]);

        assert!(filter.contains(&b"string bytes".to_vec()));
        assert!(filter.contains(b"static bytes"));
        assert!(filter.contains(&42u64.to_le_bytes()));
        assert!(filter.contains(&[1u8, 2, 3, 4, 5]));
        Ok(())
    }

    #[test]
    fn test_bloom_filter_serialization_roundtrip() -> anyhow::Result<()> {
        let config = BloomConfig::new(CAPACITY, FALSE_POSITIVE_RATE);
        let mut filter = QPBloomFilter::new(config);

        // Insert some data
        filter.insert(&b"test data 1".to_vec());
        filter.insert(&b"test data 2".to_vec());
        filter.insert(&b"test data 3".to_vec());

        // Serialize
        let bytes = filter.to_bytes()?;
        let restored: QPBloomFilter = QPBloomFilter::from_bytes(&bytes)?;

        // Verify data is preserved
        assert!(restored.contains(&b"test data 1".to_vec()));
        assert!(restored.contains(&b"test data 2".to_vec()));
        assert!(restored.contains(&b"test data 3".to_vec()));

        // Verify config is preserved
        assert_eq!(restored.config().capacity, CAPACITY);
        assert_eq!(restored.config().false_positive_rate, FALSE_POSITIVE_RATE);
        Ok(())
    }

    #[test]
    fn test_bloom_filter_config_stored() -> anyhow::Result<()> {
        let config = BloomConfig::new(1000, 0.001);
        let filter = QPBloomFilter::new(config);

        assert_eq!(filter.config().capacity, 1000);
        assert_eq!(filter.config().false_positive_rate, 0.001);
        Ok(())
    }

    #[test]
    fn test_bloom_filter_merge_basic() -> anyhow::Result<()> {
        let config = BloomConfig::new(CAPACITY, FALSE_POSITIVE_RATE);

        let mut filter1 = QPBloomFilter::new(config);
        let mut filter2 = QPBloomFilter::new(config);

        filter1.insert(&b"item1".to_vec());
        filter2.insert(&b"item2".to_vec());

        filter1.merge(&filter2)?;

        assert!(filter1.contains(&b"item1".to_vec()));
        assert!(filter1.contains(&b"item2".to_vec()));
        Ok(())
    }

    #[test]
    fn test_bloom_filter_merge_preserves_config() -> anyhow::Result<()> {
        let config = BloomConfig::new(CAPACITY, FALSE_POSITIVE_RATE);

        let mut filter1 = QPBloomFilter::new(config);
        let mut filter2 = QPBloomFilter::new(config);

        filter1.insert(&b"item1".to_vec());
        filter2.insert(&b"item2".to_vec());

        filter1.merge(&filter2)?;

        // Config should be preserved
        assert_eq!(filter1.config().capacity, CAPACITY);
        assert_eq!(filter1.config().false_positive_rate, FALSE_POSITIVE_RATE);
        Ok(())
    }

    #[test]
    fn test_bloom_filter_merge_invalid_bytes() -> anyhow::Result<()> {
        let config = BloomConfig::new(CAPACITY, FALSE_POSITIVE_RATE);

        let mut filter1 = QPBloomFilter::new(config);
        let mut filter2 = QPBloomFilter::new(config);

        filter1.insert(&b"item1".to_vec());
        filter2.insert(&b"item2".to_vec());

        // Corrupt bytes - not valid bincode
        let mut corrupted_bytes = vec![0u8; 10];
        corrupted_bytes[0] = 0xff; // Invalid bincode marker

        let result = QPBloomFilter::from_bytes(&corrupted_bytes);
        assert!(result.is_err(), "Invalid bytes should fail to deserialize");
        Ok(())
    }

    #[test]
    fn test_bloom_filter_merge_preserves_other_filter() -> anyhow::Result<()> {
        // Verify that merging doesn't modify the other filter
        let config = BloomConfig::new(CAPACITY, FALSE_POSITIVE_RATE);

        let mut filter1 = QPBloomFilter::new(config);
        let mut filter2 = QPBloomFilter::new(config);

        let items: Vec<Vec<u8>> = (0..20).map(|i| format!("item_{}", i).into_bytes()).collect();

        for item in &items {
            filter2.insert(item);
        }

        let filter2_bytes_before = filter2.to_bytes()?;

        // Merge filter2 into filter1
        filter1.merge(&filter2)?;

        // filter2 should be unchanged
        let filter2_bytes_after = filter2.to_bytes()?;
        assert_eq!(filter2_bytes_before, filter2_bytes_after, "Merging should not modify the source filter");

        // All filter2 items should still be findable in filter2
        for item in &items {
            assert!(filter2.contains(item), "Item should still be in filter2 after merge");
        }
        Ok(())
    }

    #[test]
    fn test_bloom_filter_merge_large_item_counts() -> anyhow::Result<()> {
        // Test with larger numbers of items
        let config = BloomConfig::new(10000, 0.0001); // Higher capacity, lower FPR

        let mut filter1 = QPBloomFilter::new(config);
        let mut filter2 = QPBloomFilter::new(config);

        // Insert 500 items into filter1
        for i in 0..500 {
            filter1.insert(&format!("filter1_large_{}", i).into_bytes());
        }

        // Insert 300 items into filter2
        for i in 0..300 {
            filter2.insert(&format!("filter2_large_{}", i).into_bytes());
        }

        filter1.merge(&filter2)?;

        // Verify all items are present
        for i in 0..500 {
            assert!(
                filter1.contains(&format!("filter1_large_{}", i).into_bytes()),
                "filter1_large_{} should be found after merge",
                i
            );
        }

        for i in 0..300 {
            assert!(
                filter1.contains(&format!("filter2_large_{}", i).into_bytes()),
                "filter2_large_{} should be found after merge",
                i
            );
        }
        Ok(())
    }

    #[test]
    fn test_bloom_filter_merge_different_capacity() -> anyhow::Result<()> {
        let config1 = BloomConfig::new(100, FALSE_POSITIVE_RATE);
        let config2 = BloomConfig::new(200, FALSE_POSITIVE_RATE);

        let mut filter1 = QPBloomFilter::new(config1);
        let mut filter2 = QPBloomFilter::new(config2);

        filter1.insert(&b"item1".to_vec());
        filter2.insert(&b"item2".to_vec());

        let result = filter1.merge(&filter2);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("different configurations"));
        Ok(())
    }

    #[test]
    fn test_bloom_filter_merge_different_fpr() -> anyhow::Result<()> {
        let config1 = BloomConfig::new(CAPACITY, 0.01);
        let config2 = BloomConfig::new(CAPACITY, 0.001);

        let mut filter1 = QPBloomFilter::new(config1);
        let mut filter2 = QPBloomFilter::new(config2);

        filter1.insert(&b"item1".to_vec());
        filter2.insert(&b"item2".to_vec());

        let result = filter1.merge(&filter2);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("different configurations"));
        Ok(())
    }

    #[test]
    fn test_bloom_filter_merge_empty_filters() -> anyhow::Result<()> {
        let config = BloomConfig::new(CAPACITY, FALSE_POSITIVE_RATE);

        let mut filter1 = QPBloomFilter::new(config);
        let mut filter2 = QPBloomFilter::new(config);

        filter1.insert(&b"item1".to_vec());
        // filter2 is empty

        filter1.merge(&filter2)?;

        // Should still contain item1
        assert!(filter1.contains(&b"item1".to_vec()));
        Ok(())
    }

    #[test]
    fn test_bloom_filter_merge_both_empty() -> anyhow::Result<()> {
        let config = BloomConfig::new(CAPACITY, FALSE_POSITIVE_RATE);

        let mut filter1 = QPBloomFilter::new(config);
        let mut filter2 = QPBloomFilter::new(config);

        // Both empty
        filter1.merge(&filter2)?;

        // Should be empty (no false positives for empty filter)
        assert!(!filter1.contains(b"any"));
        Ok(())
    }

    #[test]
    fn test_bloom_filter_merge_different_item_counts() -> anyhow::Result<()> {
        let config = BloomConfig::new(CAPACITY, FALSE_POSITIVE_RATE);

        let mut filter1 = QPBloomFilter::new(config);
        let mut filter2 = QPBloomFilter::new(config);

        // Filter1: insert 50 items
        for i in 0..50 {
            filter1.insert(&format!("filter1_item_{}", i).into_bytes());
        }

        // Filter2: insert 10 items (different count)
        for i in 0..10 {
            filter2.insert(&format!("filter2_item_{}", i).into_bytes());
        }

        filter1.merge(&filter2)?;

        // All items from both filters should be present
        for i in 0..50 {
            assert!(
                filter1.contains(&format!("filter1_item_{}", i).into_bytes()),
                "filter1_item_{} should be found after merge",
                i
            );
        }

        for i in 0..10 {
            assert!(
                filter1.contains(&format!("filter2_item_{}", i).into_bytes()),
                "filter2_item_{} should be found after merge",
                i
            );
        }

        // Config should be preserved
        assert_eq!(filter1.config().capacity, CAPACITY);
        assert_eq!(filter1.config().false_positive_rate, FALSE_POSITIVE_RATE);
        Ok(())
    }

    #[test]
    fn test_bloom_filter_merge_multiple_filters() -> anyhow::Result<()> {
        let config = BloomConfig::new(CAPACITY, FALSE_POSITIVE_RATE);

        let mut result_filter = QPBloomFilter::new(config);
        let filters: Vec<QPBloomFilter> = (0..5)
            .map(|i| {
                let mut f = QPBloomFilter::new(config);
                f.insert(&format!("item_{}", i).into_bytes());
                f
            })
            .collect();

        // Merge all filters into result
        for f in filters.iter() {
            result_filter.merge(f)?;
        }

        // All items should be present
        for i in 0..5 {
            assert!(result_filter.contains(&format!("item_{}", i).into_bytes()));
        }
        Ok(())
    }

    #[test]
    fn test_bloom_filter_merge_idempotent() -> anyhow::Result<()> {
        let config = BloomConfig::new(CAPACITY, FALSE_POSITIVE_RATE);

        let mut filter1 = QPBloomFilter::new(config);
        let mut filter2 = QPBloomFilter::new(config);

        filter1.insert(&b"shared_item0".to_vec());
        filter1.insert(&b"shared_item1".to_vec());
        filter2.insert(&b"shared_item2".to_vec());

        // Merge multiple times should not change result
        filter1.merge(&filter2)?;
        filter1.merge(&filter2)?;
        filter1.merge(&filter2)?;

        assert!(filter1.contains(&b"shared_item2".to_vec()));
        Ok(())
    }

    #[test]
    fn test_bloom_filter_false_positive_rate() -> anyhow::Result<()> {
        // Test that the false positive rate is roughly as expected
        let config = BloomConfig::new(10000, 0.01); // 1% FPR
        let mut filter = QPBloomFilter::new(config);

        // Insert known items
        for i in 0..1000 {
            filter.insert(&format!("known_item_{}", i).into_bytes());
        }

        // Check that all known items are found
        for i in 0..1000 {
            assert!(filter.contains(&format!("known_item_{}", i).into_bytes()));
        }

        // Check some unknown items - allow for some false positives
        // but most should not be found
        let mut false_positives = 0;
        let test_count = 1000;

        for i in 0..test_count {
            if filter.contains(&format!("unknown_item_{}", i).into_bytes()) {
                false_positives += 1;
            }
        }

        // False positive rate should be roughly 1%
        // Allow some variance but should be within reasonable bounds
        let actual_rate = false_positives as f64 / test_count as f64;
        assert!(actual_rate < 0.05, "False positive rate too high: {}%", actual_rate * 100.0);
        Ok(())
    }

    #[test]
    fn test_bloom_filter_inner_access() -> anyhow::Result<()> {
        let config = BloomConfig::new(CAPACITY, FALSE_POSITIVE_RATE);
        let filter = QPBloomFilter::new(config);

        // Access inner filter
        let _inner = filter.inner();
        Ok(())
    }

    #[test]
    fn test_bloom_filter_clone() -> anyhow::Result<()> {
        let config = BloomConfig::new(CAPACITY, FALSE_POSITIVE_RATE);
        let mut filter1 = QPBloomFilter::new(config);

        filter1.insert(&b"test_item".to_vec());

        // Clone
        let filter2 = filter1.clone();

        // Cloned filter should contain the same data
        assert!(filter2.contains(&b"test_item".to_vec()));

        // Config should be the same
        assert_eq!(filter2.config().capacity, CAPACITY);
        Ok(())
    }

    #[cfg(feature = "rand_gen")]
    #[test]
    fn test_bloom_filter_add_events_random() -> anyhow::Result<()> {
        const EVENT_COUNT: usize = 65536;

        // Generate random events using QPGenRandom
        let events = PsyUserEventRecord::<parth_core::PF>::qp_rand_gen_vec(EVENT_COUNT);

        // Test with different configs (matching the size test)
        for (capacity, fpr) in [
            (EVENT_COUNT * 6, 0.001), // 65536 * 6 = 393216
            (EVENT_COUNT * 6, 0.01),
            (EVENT_COUNT * 12, 0.001), // 65536 * 12 = 786432
        ] {
            use crate::v1::qdata::bloom_filter::EventFilter;

            let config = BloomConfig::new(capacity, fpr);
            let mut filter = QPBloomFilter::new(config);

            // Use add_events to insert all events
            filter.add_events(events.iter());

            // Get serialized size
            let bytes = filter.to_bytes()?;
            let size_kb = bytes.len() as f64 / 1024.0;

            println!(
                "Random events ({}): Capacity: {}, FPR: {:.3}, Serialized size: {:.2} KB ({:.2} MB)",
                EVENT_COUNT,
                capacity,
                fpr,
                size_kb,
                size_kb / 1024.0
            );

            // Verify all events are findable
            for event in &events {
                use crate::v1::qdata::bloom_filter::EventBloomItem;

                assert!(filter.contains(&event.action_key()), "Action key should be found");
                assert!(filter.contains(&event.user_key()), "User key should be found");
                assert!(filter.contains(&event.contract_key()), "Contract key should be found");
            }
        }

        Ok(())
    }
}
