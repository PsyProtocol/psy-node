use kvq::traits::KVQSerializable;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::RichField};
use psy_client_common::{
    data::qhashout::QHashOut,
    traits::to_qfelts::{QFeltSized, ToQFelts},
};
use psy_crypto::hash::traits::{hasher::FieldQHasher, qhashable::QFieldHashable};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Leaf preimage for an Indexed Merkle Tree (IMT) leaf in a contract state
/// tree.
///
/// Each leaf in an IMT stores:
/// - `key`: the 256-bit storage key (e.g., nullifier hash, mapping key)
/// - `value`: the 256-bit storage value
/// - `next_key`: the key of the successor leaf in sorted order (zero = no
///   successor)
/// - `next_index`: the leaf index of the successor in the tree (zero = no
///   successor)
///
/// The leaf hash is computed from all 13 field elements via Poseidon hashing.
/// Index 0 is always the sentinel leaf with all fields set to zero.
///
/// This structure matches the chain-side `IMTContractStateLeaf` defined in
/// `psy_client_data/src/v1/qdata/contract/imt_leaf.rs` in the node codebase.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct IMTContractStateLeaf<F: RichField> {
    /// 256-bit storage key (4 field elements)
    pub key: QHashOut<F>,
    /// 256-bit storage value (4 field elements)
    pub value: QHashOut<F>,
    /// Key of the successor leaf in sorted order (zero = end of list)
    pub next_key: QHashOut<F>,
    /// Leaf index of the successor (zero = end of list)
    pub next_index: F,
}

impl<F: RichField> IMTContractStateLeaf<F> {
    /// Create the sentinel leaf (all zeros) — always at index 0.
    pub fn sentinel() -> Self {
        Self::default()
    }

    /// Check if this is the sentinel leaf (all zeros).
    pub fn is_sentinel(&self) -> bool {
        self.key == QHashOut::ZERO && self.value == QHashOut::ZERO && self.next_key == QHashOut::ZERO && self.next_index == F::ZERO
    }

    /// Check if this leaf is the last in the sorted linked list (no successor).
    pub fn is_last(&self) -> bool {
        self.next_key == QHashOut::ZERO && self.next_index == F::ZERO
    }

    /// Create a new leaf with the given key, value, and linked-list pointers.
    pub fn new(key: QHashOut<F>, value: QHashOut<F>, next_key: QHashOut<F>, next_index: F) -> Self {
        Self {
            key,
            value,
            next_key,
            next_index,
        }
    }

    /// Create an updated copy with a new value (key and pointers unchanged).
    pub fn with_new_value(&self, new_value: QHashOut<F>) -> Self {
        Self {
            key: self.key,
            value: new_value,
            next_key: self.next_key,
            next_index: self.next_index,
        }
    }

    /// Create an updated copy with new linked-list pointers (key and value
    /// unchanged).
    pub fn with_new_next(&self, next_key: QHashOut<F>, next_index: F) -> Self {
        Self {
            key: self.key,
            value: self.value,
            next_key,
            next_index,
        }
    }
}

impl<F: RichField> KVQSerializable for IMTContractStateLeaf<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> QFeltSized for IMTContractStateLeaf<F> {
    fn q_felt_size() -> usize {
        13 // key(4) + value(4) + next_key(4) + next_index(1)
    }
}

impl<F: RichField> ToQFelts<F> for IMTContractStateLeaf<F> {
    fn to_qfelts(&self) -> Vec<F> {
        vec![
            self.key.0.elements[0],
            self.key.0.elements[1],
            self.key.0.elements[2],
            self.key.0.elements[3],
            self.value.0.elements[0],
            self.value.0.elements[1],
            self.value.0.elements[2],
            self.value.0.elements[3],
            self.next_key.0.elements[0],
            self.next_key.0.elements[1],
            self.next_key.0.elements[2],
            self.next_key.0.elements[3],
            self.next_index,
        ]
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != 13 {
            panic!("Invalid number of elements for IMTContractStateLeaf: expected 13, got {}", felts.len());
        }
        let key = QHashOut::from_qfelts(&felts[0..4]);
        let value = QHashOut::from_qfelts(&felts[4..8]);
        let next_key = QHashOut::from_qfelts(&felts[8..12]);
        let next_index = felts[12];
        IMTContractStateLeaf {
            key,
            value,
            next_key,
            next_index,
        }
    }
}

impl<F: RichField> QFieldHashable<F> for IMTContractStateLeaf<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        H::q_hash_many(&[
            self.key.0.elements[0],
            self.key.0.elements[1],
            self.key.0.elements[2],
            self.key.0.elements[3],
            self.value.0.elements[0],
            self.value.0.elements[1],
            self.value.0.elements[2],
            self.value.0.elements[3],
            self.next_key.0.elements[0],
            self.next_key.0.elements[1],
            self.next_key.0.elements[2],
            self.next_key.0.elements[3],
            self.next_index,
        ])
    }
}

/// Ordering for QHashOut values using MSL-first comparison.
///
/// Compares the 4 field elements as u64 values with the most-significant limb
/// (elements[3]) dominating. This matches the key ordering used by the
/// chain-side indexed merkle tree and the ScyllaDB sort-encoded key format.
pub fn compare_qhashout_keys<F: RichField>(a: &QHashOut<F>, b: &QHashOut<F>) -> std::cmp::Ordering {
    // MSL first: elements[3] > elements[2] > elements[1] > elements[0]
    for i in (0..4).rev() {
        let a_val = a.0.elements[i].to_canonical_u64();
        let b_val = b.0.elements[i].to_canonical_u64();
        match a_val.cmp(&b_val) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

/// Encode a QHashOut key into a 32-byte comparison-compatible format for sorted
/// storage.
///
/// MSL-first with each limb in big-endian byte order, so byte-by-byte
/// lexicographic comparison matches numerical ordering.
pub fn encode_key_for_sorting<F: RichField>(key: &QHashOut<F>) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    // MSL first, each limb in big-endian
    bytes[0..8].copy_from_slice(&key.0.elements[3].to_canonical_u64().to_be_bytes());
    bytes[8..16].copy_from_slice(&key.0.elements[2].to_canonical_u64().to_be_bytes());
    bytes[16..24].copy_from_slice(&key.0.elements[1].to_canonical_u64().to_be_bytes());
    bytes[24..32].copy_from_slice(&key.0.elements[0].to_canonical_u64().to_be_bytes());
    bytes
}

/// Decode a comparison-compatible encoded key back to a QHashOut.
pub fn decode_key_from_sorting<F: RichField>(bytes: &[u8; 32]) -> QHashOut<F> {
    let e3 = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
    let e2 = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
    let e1 = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
    let e0 = u64::from_be_bytes(bytes[24..32].try_into().unwrap());
    QHashOut::from_values(e0, e1, e2, e3)
}

/// Compute the bucket index for a comparison-encoded key.
/// Bucket = first 2 bytes of the sort-encoded key → 65,536 buckets per
/// contract.
pub fn key_bucket(encoded_key: &[u8; 32]) -> i16 {
    i16::from_be_bytes([encoded_key[0], encoded_key[1]])
}

#[cfg(test)]
mod tests {
    use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};
    use psy_crypto::hash::traits::hasher::PoseidonHasher;

    use super::*;

    type F = GoldilocksField;

    #[test]
    fn test_sentinel_leaf() {
        let sentinel = IMTContractStateLeaf::<F>::sentinel();
        assert!(sentinel.is_sentinel());
        assert_eq!(sentinel.key, QHashOut::ZERO);
        assert_eq!(sentinel.value, QHashOut::ZERO);
        assert_eq!(sentinel.next_key, QHashOut::ZERO);
        assert_eq!(sentinel.next_index, F::ZERO);
    }

    #[test]
    fn test_non_sentinel_leaf() {
        let leaf = IMTContractStateLeaf::<F>::new(
            QHashOut::from_values(1, 2, 3, 4),
            QHashOut::from_values(5, 6, 7, 8),
            QHashOut::from_values(9, 10, 11, 12),
            F::from_canonical_u64(42),
        );
        assert!(!leaf.is_sentinel());
    }

    #[test]
    fn test_felt_size() {
        assert_eq!(IMTContractStateLeaf::<F>::q_felt_size(), 13);
    }

    #[test]
    fn test_to_from_qfelts_roundtrip() {
        let leaf = IMTContractStateLeaf::<F>::new(
            QHashOut::from_values(1, 2, 3, 4),
            QHashOut::from_values(5, 6, 7, 8),
            QHashOut::from_values(9, 10, 11, 12),
            F::from_canonical_u64(42),
        );
        let felts = leaf.to_qfelts();
        assert_eq!(felts.len(), 13);
        let recovered = IMTContractStateLeaf::<F>::from_qfelts(&felts);
        assert_eq!(leaf, recovered);
    }

    #[test]
    fn test_hash_consistency() {
        let leaf = IMTContractStateLeaf::<F>::new(
            QHashOut::from_values(1, 2, 3, 4),
            QHashOut::from_values(5, 6, 7, 8),
            QHashOut::from_values(9, 10, 11, 12),
            F::from_canonical_u64(42),
        );
        let hash1 = leaf.qfhash::<PoseidonHasher>();
        let hash2 = leaf.qfhash::<PoseidonHasher>();
        assert_eq!(hash1, hash2, "Hash should be deterministic");
        assert_ne!(hash1, QHashOut::ZERO, "Hash should not be zero for non-zero input");
    }

    #[test]
    fn test_different_values_different_hashes() {
        let leaf1 = IMTContractStateLeaf::<F>::new(QHashOut::from_values(1, 0, 0, 0), QHashOut::ZERO, QHashOut::ZERO, F::ZERO);
        let leaf2 = IMTContractStateLeaf::<F>::new(QHashOut::from_values(2, 0, 0, 0), QHashOut::ZERO, QHashOut::ZERO, F::ZERO);
        assert_ne!(leaf1.qfhash::<PoseidonHasher>(), leaf2.qfhash::<PoseidonHasher>());
    }

    #[test]
    fn test_with_new_value() {
        let leaf = IMTContractStateLeaf::<F>::new(
            QHashOut::from_values(1, 2, 3, 4),
            QHashOut::from_values(5, 6, 7, 8),
            QHashOut::from_values(9, 10, 11, 12),
            F::from_canonical_u64(42),
        );
        let updated = leaf.with_new_value(QHashOut::from_values(100, 200, 300, 400));
        assert_eq!(updated.key, leaf.key);
        assert_eq!(updated.value, QHashOut::from_values(100, 200, 300, 400));
        assert_eq!(updated.next_key, leaf.next_key);
        assert_eq!(updated.next_index, leaf.next_index);
    }

    #[test]
    fn test_with_new_next() {
        let leaf = IMTContractStateLeaf::<F>::new(
            QHashOut::from_values(1, 2, 3, 4),
            QHashOut::from_values(5, 6, 7, 8),
            QHashOut::from_values(9, 10, 11, 12),
            F::from_canonical_u64(42),
        );
        let updated = leaf.with_new_next(QHashOut::from_values(100, 200, 300, 400), F::from_canonical_u64(99));
        assert_eq!(updated.key, leaf.key);
        assert_eq!(updated.value, leaf.value);
        assert_eq!(updated.next_key, QHashOut::from_values(100, 200, 300, 400));
        assert_eq!(updated.next_index, F::from_canonical_u64(99));
    }

    #[test]
    fn test_key_comparison_msl_dominates() {
        let a = QHashOut::<F>::from_values(u64::MAX, u64::MAX, u64::MAX, 0);
        let b = QHashOut::<F>::from_values(0, 0, 0, 1);
        assert_eq!(compare_qhashout_keys(&a, &b), std::cmp::Ordering::Less);
    }

    #[test]
    fn test_key_comparison_equal() {
        let a = QHashOut::<F>::from_values(1, 2, 3, 4);
        let b = QHashOut::<F>::from_values(1, 2, 3, 4);
        assert_eq!(compare_qhashout_keys(&a, &b), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_key_comparison_lsl_tiebreak() {
        let a = QHashOut::<F>::from_values(1, 0, 0, 0);
        let b = QHashOut::<F>::from_values(2, 0, 0, 0);
        assert_eq!(compare_qhashout_keys(&a, &b), std::cmp::Ordering::Less);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let key = QHashOut::<F>::from_values(1, 2, 3, 4);
        let encoded = encode_key_for_sorting(&key);
        let decoded = decode_key_from_sorting::<F>(&encoded);
        assert_eq!(key, decoded);
    }

    #[test]
    fn test_encoding_preserves_ordering() {
        let a = QHashOut::<F>::from_values(100, 200, 300, 1);
        let b = QHashOut::<F>::from_values(100, 200, 300, 2);
        let enc_a = encode_key_for_sorting(&a);
        let enc_b = encode_key_for_sorting(&b);
        assert!(enc_a < enc_b);
    }

    #[test]
    fn test_bucket_extraction() {
        let key = QHashOut::<F>::from_values(0, 0, 0, 0x0102_0000_0000_0000);
        let encoded = encode_key_for_sorting(&key);
        let bucket = key_bucket(&encoded);
        assert_eq!(bucket, 0x0102i16);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let leaf = IMTContractStateLeaf::<F>::new(
            QHashOut::from_values(1, 2, 3, 4),
            QHashOut::from_values(5, 6, 7, 8),
            QHashOut::from_values(9, 10, 11, 12),
            F::from_canonical_u64(42),
        );
        let bytes = leaf.to_bytes().unwrap();
        let recovered = IMTContractStateLeaf::<F>::from_bytes(&bytes).unwrap();
        assert_eq!(leaf, recovered);
    }
}
