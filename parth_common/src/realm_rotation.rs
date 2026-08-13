//! Realm instance rotation protocol.
//!
//! Each target checkpoint, a deterministic Poseidon swap-or-not schedule
//! selects which Realm validator instance is the proposer. The permutation
//! starts at index 0 and is seeded by the epoch of the target checkpoint
//! (not a per-checkpoint slot), so one proposer is fixed for the whole epoch;
//! only that proposer may submit GUTA for that Realm at any target checkpoint
//! in the epoch.

use parth_core::{
    crypto::hash::traits::{FieldQHasher, HashTo4Felts},
    felt::{FromPrimitiveValuesFelt, ToU64Value},
    pgoldilocks::PoseidonHasher,
    PHash, PF,
};

/// Domain separator for the per-Realm, per-epoch schedule seed.
pub const SCHEDULE_DOMAIN: u64 = u64::from_le_bytes(*b"PSYROT02");

/// Domain separator for each swap-or-not round's pivot.
pub const PIVOT_DOMAIN: u64 = u64::from_le_bytes(*b"PIVOTV01");

/// Domain separator for each swap-or-not round's source bit.
pub const SOURCE_DOMAIN: u64 = u64::from_le_bytes(*b"SOURCE01");

/// Canonical Goldilocks field limbs from the anchor checkpoint's random seed.
pub type RotationAnchorSeed = [u64; 4];

const GOLDILOCKS_FIELD_ORDER: u64 = 0xffff_ffff_0000_0001;

/// Coordinator-side rotation configuration.
///
/// When `validator_sub_ids` is non-empty, the Coordinator enforces that only
/// the current epoch's proposer may submit GUTA. When empty, rotation is disabled
/// and all submissions are accepted (backward compatible).
#[derive(Clone, Debug)]
pub struct RealmRotationConfig {
    pub checkpoints_per_epoch: u64,
    /// Sorted list of registered `realm_sub_id` values for this Realm.
    pub validator_sub_ids: Vec<u16>,
}

impl RealmRotationConfig {
    /// Returns `true` if rotation enforcement is active.
    pub fn is_enabled(&self) -> bool {
        self.checkpoints_per_epoch > 0 && !self.validator_sub_ids.is_empty()
    }

    /// Returns the proposer's `realm_sub_id` for the given target checkpoint,
    /// or `None` if rotation is disabled.
    ///
    /// `checkpoint_id` is the target checkpoint `T`. Production scheduled
    /// ownership evaluates `T = P + 1`; this function does not convert a proof
    /// checkpoint `P` into `T`.
    ///
    /// The epoch calculation, epoch-anchor seed derivation, domains, and 90
    /// swap-or-not rounds are unchanged. The permutation always starts at
    /// index 0 so every target checkpoint in an epoch selects the same proposer.
    pub fn proposer_sub_id(
        &self,
        realm_id: u32,
        checkpoint_id: u64,
        anchor_seed: RotationAnchorSeed,
    ) -> anyhow::Result<Option<u16>> {
        if !self.is_enabled() {
            return Ok(None);
        }
        anyhow::ensure!(
            anchor_seed.iter().all(|&limb| limb < GOLDILOCKS_FIELD_ORDER),
            "rotation anchor seed contains a noncanonical Goldilocks field element",
        );

        let n = self.validator_sub_ids.len();
        let epoch = epoch(checkpoint_id, self.checkpoints_per_epoch);
        let anchor_seed = anchor_seed.map(PF::from_u64_value);
        let seed: PHash = PoseidonHasher::q_hash_many(&[
            PF::from_u64_value(SCHEDULE_DOMAIN),
            PF::from_u64_value(realm_id as u64),
            PF::from_u64_value(epoch & 0xffff_ffff),
            PF::from_u64_value(epoch >> 32),
            anchor_seed[0],
            anchor_seed[1],
            anchor_seed[2],
            anchor_seed[3],
        ]);
        let seed = seed.to_4_felts();

        let mut index = 0;
        for round in 0..90u64 {
            let pivot_hash: PHash = PoseidonHasher::q_hash_many(&[
                PF::from_u64_value(PIVOT_DOMAIN),
                seed[0],
                seed[1],
                seed[2],
                seed[3],
                PF::from_u64_value(round),
            ]);
            let pivot_word = pivot_hash.to_4_felts()[0].tuv_to_canonical_u64() as u32;
            let pivot = (pivot_word as usize) % n;
            let flip = (pivot + n - index) % n;
            let position = index.max(flip);
            let source_hash: PHash = PoseidonHasher::q_hash_many(&[
                PF::from_u64_value(SOURCE_DOMAIN),
                seed[0],
                seed[1],
                seed[2],
                seed[3],
                PF::from_u64_value(round),
                PF::from_u64_value(position as u64),
            ]);
            if source_hash.to_4_felts()[0].tuv_to_canonical_u64() & 1 == 1 {
                index = flip;
            }
        }

        Ok(Some(self.validator_sub_ids[index]))
    }
}

/// Compute the epoch index for a given target checkpoint.
pub fn epoch(checkpoint_id: u64, checkpoints_per_epoch: u64) -> u64 {
    checkpoint_id / checkpoints_per_epoch
}

/// Checkpoint whose `random_seed` anchors the schedule for `epoch`.
///
/// Returns the **last** checkpoint of the *previous* epoch, which is committed
/// before the current epoch starts. Epoch 0 anchors at checkpoint 0 (genesis).
pub fn anchor_checkpoint_id(epoch: u64, checkpoints_per_epoch: u64) -> u64 {
    (epoch * checkpoints_per_epoch).saturating_sub(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(values: [u64; 4]) -> RotationAnchorSeed {
        values
    }

    fn config(n: usize, period: u64) -> RealmRotationConfig {
        RealmRotationConfig {
            checkpoints_per_epoch: period,
            validator_sub_ids: (0..n).map(|index| index as u16).collect(),
        }
    }

    fn selected_index(
        n: usize,
        realm_id: u32,
        checkpoint_id: u64,
        period: u64,
        anchor_seed: RotationAnchorSeed,
    ) -> usize {
        config(n, period)
            .proposer_sub_id(realm_id, checkpoint_id, anchor_seed)
            .unwrap()
            .unwrap() as usize
    }

    #[test]
    fn test_domain_constants() {
        assert_eq!(SCHEDULE_DOMAIN, 0x3230_544f_5259_5350);
        assert_eq!(PIVOT_DOMAIN, 0x3130_5654_4f56_4950);
        assert_eq!(SOURCE_DOMAIN, 0x3130_4543_5255_4f53);
    }

    #[test]
    fn test_rotation_disabled() {
        assert_eq!(config(0, 10).proposer_sub_id(1, 0, seed([0; 4])).unwrap(), None);
        assert_eq!(config(3, 0).proposer_sub_id(1, 0, seed([0; 4])).unwrap(), None);
    }

    #[test]
    fn test_single_element() {
        let rotation = config(1, 10);
        for (realm_id, checkpoint_id, anchor_seed) in [
            (0, 0, seed([0; 4])),
            (42, 17, seed([1, 2, 3, 4])),
            (u32::MAX, u64::MAX, seed([GOLDILOCKS_FIELD_ORDER - 1; 4])),
        ] {
            assert_eq!(
                rotation.proposer_sub_id(realm_id, checkpoint_id, anchor_seed).unwrap(),
                Some(0),
            );
        }
    }

    #[test]
    fn test_noncanonical_anchor_seed_is_rejected() {
        let error = config(2, 10)
            .proposer_sub_id(1, 0, seed([0, 0, 0, GOLDILOCKS_FIELD_ORDER]))
            .unwrap_err();
        assert!(error.to_string().contains("noncanonical Goldilocks"));
    }

    #[test]
    fn test_deterministic() {
        let rotation = config(256, 10);
        let anchor_seed = seed([1, 2, 3, 4]);
        let first = rotation.proposer_sub_id(42, 17, anchor_seed).unwrap();
        let second = rotation.proposer_sub_id(42, 17, anchor_seed).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn test_epoch_boundaries_share_schedule() {
        let rotation = config(256, 10);
        let anchor_seed = seed([5, 8, 13, 21]);
        assert_eq!(
            rotation.proposer_sub_id(7, 10, anchor_seed).unwrap(),
            rotation.proposer_sub_id(7, 19, anchor_seed).unwrap(),
        );
        assert_ne!(
            rotation.proposer_sub_id(7, 9, anchor_seed).unwrap(),
            rotation.proposer_sub_id(7, 10, anchor_seed).unwrap(),
        );
    }

    #[test]
    fn test_realm_separates_schedule() {
        let rotation = config(256, 10);
        let anchor_seed = seed([5, 8, 13, 21]);
        assert_ne!(
            rotation.proposer_sub_id(1, 17, anchor_seed).unwrap(),
            rotation.proposer_sub_id(2, 17, anchor_seed).unwrap(),
        );
    }

    #[test]
    fn test_epoch_and_anchor() {
        assert_eq!(epoch(0, 10), 0);
        assert_eq!(epoch(9, 10), 0);
        assert_eq!(epoch(10, 10), 1);
        assert_eq!(epoch(19, 10), 1);
        assert_eq!(epoch(20, 10), 2);

        assert_eq!(anchor_checkpoint_id(0, 10), 0);
        assert_eq!(anchor_checkpoint_id(1, 10), 9);
        assert_eq!(anchor_checkpoint_id(2, 10), 19);
    }

    #[test]
    fn test_proposer_index_in_range() {
        for &n in &[1usize, 2, 3, 10, 100, 256] {
            for anchor_seed in [seed([0; 4]), seed([GOLDILOCKS_FIELD_ORDER - 1; 4])] {
                let index = selected_index(n, 42, 17, 10, anchor_seed);
                assert!(index < n, "proposer index {index} out of range for n={n}");
            }
        }
    }

    #[test]
    fn test_fixed_vectors() {
        let vectors = [
            // n = 1: start index is always 0.
            (1, 1, 0, 10, seed([0; 4]), 0),
            // period 1: every target checkpoint is its own epoch; start stays 0.
            (3, 0xdead_beef, 0x1_0000_0005, 1, seed([5, 8, 13, 21]), 0),
        ];
        for (n, realm_id, target_checkpoint, period, anchor_seed, expected_index) in vectors {
            assert_eq!(
                selected_index(n, realm_id, target_checkpoint, period, anchor_seed),
                expected_index,
            );
        }
    }
}
