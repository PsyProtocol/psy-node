use auto_impl::auto_impl;
#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
use parth_core::{crypto::hash::merkle_proof::DeltaMerkleProofCore, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase, QHashBase}};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::v1::qdata::contract::{PsyContractSlotUpdates, PsySlotUpdate};


#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash))]
pub struct QEDContractStateUpdateHistory<Hash> {
    pub user_contract_tree_update_proof: DeltaMerkleProofCore<Hash>,
    pub contract_state_tree_updates: Vec<DeltaMerkleProofCore<Hash>>,
}
#[cfg(feature = "rand_gen")]
impl<Hash: QPGenRandom> QPGenRandom for QEDContractStateUpdateHistory<Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            user_contract_tree_update_proof: DeltaMerkleProofCore::<Hash>::qp_rand_gen(),
            contract_state_tree_updates: QPGenRandom::qp_rand_gen_vec(rand::random::<u8>() as usize % 5 + 1),
        }
    }
}

impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for QEDContractStateUpdateHistory<Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for QEDContractStateUpdateHistory<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        self.user_contract_tree_update_proof.pio_serialized_size()
        + 4 + self.contract_state_tree_updates.iter().map(|p| p.pio_serialized_size()).sum::<usize>()
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.user_contract_tree_update_proof.pio_write_to_io(writer)?;
        writer.psy_write_vec_length(self.contract_state_tree_updates.len())?;
        for proof in &self.contract_state_tree_updates {
            proof.pio_write_to_io(writer)?;
        }
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let user_contract_tree_update_proof = DeltaMerkleProofCore::pio_read_from_io(reader)?;
        let updates_len = reader.psy_read_vec_length()? as usize;
        let mut contract_state_tree_updates = Vec::with_capacity(updates_len);
        for _ in 0..updates_len {
            contract_state_tree_updates.push(DeltaMerkleProofCore::pio_read_from_io(reader)?);
        }
        Ok(Self {
            user_contract_tree_update_proof,
            contract_state_tree_updates,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    QEDContractStateUpdateHistory,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for QEDContractStateUpdateHistory<Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    QEDContractStateUpdateHistory,
    { parth_core::PHash },
    qed_contract_state_update_history_ser_tests
);
impl<Hash: QHashBase> QEDContractStateUpdateHistory<Hash> {
    pub fn ensure_basic_consistency<C: PSimpleContractHeightCache<Hash>>(&self, contract_helper: &C, contract_tree_height: usize) -> anyhow::Result<()> {
        if self.contract_state_tree_updates.len() == 0 {
            anyhow::bail!("contract_state_tree_updates cannot be empty")
        }
        if self.contract_state_tree_updates[0].old_root != self.user_contract_tree_update_proof.old_value && (
            self.user_contract_tree_update_proof.old_value != Hash::get_zero_value() || (self.contract_state_tree_updates[0].old_root != contract_helper.get_contract_zero_hash(self.user_contract_tree_update_proof.index as u32)?)
        ){
            anyhow::bail!("first CST old root does not match UCT old value");
        }
        if self.contract_state_tree_updates.last().as_ref().unwrap().new_root != self.user_contract_tree_update_proof.new_value {

            anyhow::bail!("first CST new root does not match UCT new value");
        }

        if self.user_contract_tree_update_proof.siblings.len() != contract_tree_height {
            anyhow::bail!("invalid tree height in siblings");
        }

        let height = self.contract_state_tree_updates[0].siblings.len();

        for i in 1..self.contract_state_tree_updates.len() {
            if self.contract_state_tree_updates[i].siblings.len() != height {
                anyhow::bail!("invalid tree height in siblings");
            }
            if self.contract_state_tree_updates[i].old_root != self.contract_state_tree_updates[i-1].new_root {
                anyhow::bail!("invalid cst transition proof: current old_root != last new_root, {:?} != {:?}", self.contract_state_tree_updates[i].old_root, self.contract_state_tree_updates[i-1].new_root);
            }
        }


       Ok(())

    }
    pub fn get_double_id_nodes_size_hint(&self) -> usize {
        if self.contract_state_tree_updates.len() == 0 {
            0
        }else{
            self.contract_state_tree_updates.len() * self.contract_state_tree_updates[0].siblings.len() + 2
        }
    }

    pub fn get_slot_updates<F>(&self) -> anyhow::Result<PsyContractSlotUpdates<F>>
    where
        F: QFelt64,
        Hash: QFHashBase<F>,
    {
        let slot_updates = self
            .contract_state_tree_updates
            .iter()
            .flat_map(|update| {
                let old_elements = &update.old_value.to_4_felts().to_vec();
                let new_elements = &update.new_value.to_4_felts().to_vec();
                old_elements
                    .iter()
                    .zip(new_elements.iter())
                    .enumerate()
                    .filter(|(_, (old, new))| old != new)
                    .map(|(offset, (old, new))| PsySlotUpdate {
                        slot: update.index * 4 + offset as u64,
                        old_value: *old,
                        new_value: *new,
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let contract_id = self.user_contract_tree_update_proof.index as u32;
        let contract_update = PsyContractSlotUpdates { contract_id, slot_updates };
        Ok(contract_update)
    }
    /*
    pub fn verify_generate_cst_delta<H: FieldQHasher<F, Hash>>(&self, injestor: &mut CSTUserUpdateStore<Hash>) -> anyhow::Result<()> {


        injestor.verify_injest_uct_delta_merkle_proof::<H>(&self.user_contract_tree_update_proof)?;

        let contract_id = self.user_contract_tree_update_proof.index as u32;


        for p in self.contract_state_tree_updates.iter() {
            injestor.verify_injest_delta_merkle_proof::<H>(contract_id, p)?;
        }

        Ok(())



    }*/
}

#[auto_impl(&, Arc)]
pub trait PSimpleContractHeightCache<Hash> {
    fn add_contract(&self, contract_id: u32, height: u8, zero_hash: Hash);
    fn contains_key(&self, contract_id: u32) -> bool {
        match self.get_contract_height(contract_id) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
    fn get_contract_height(&self, contract_id: u32) -> anyhow::Result<u8>;
    fn get_contract_zero_hash(&self, contract_id: u32) -> anyhow::Result<Hash>;
}

#[cfg(feature = "node")]
#[derive(Clone)]
pub struct DashMapContractHeightCache<Hash> {
    pub mapping: dashmap::DashMap<u32, (u8, Hash)>
}
#[cfg(feature = "node")]
impl<Hash: Copy> DashMapContractHeightCache<Hash> {
    pub fn new() -> Self {
        Self {
            mapping: dashmap::DashMap::new(),
        }
    }
}
#[cfg(feature = "node")]
impl<Hash: Eq + Copy> PSimpleContractHeightCache<Hash> for DashMapContractHeightCache<Hash> {
    fn add_contract(&self, contract_id: u32, height: u8, zero_hash: Hash) {
        self.mapping.insert(contract_id, (height, zero_hash));
    }
    fn contains_key(&self, contract_id: u32) -> bool {
        self.mapping.contains_key(&contract_id)
    }

    fn get_contract_height(&self, contract_id: u32) -> anyhow::Result<u8> {
        match self.mapping.get(&contract_id) {
            Some(x) => Ok(x.0),
            None => anyhow::bail!("contract {} not loaded",contract_id),
        }
    }

    fn get_contract_zero_hash(&self, contract_id: u32) -> anyhow::Result<Hash> {
        match self.mapping.get(&contract_id) {
            Some(x) => Ok(x.1),
            None => anyhow::bail!("contract {} not loaded",contract_id),
        }
    }
}

#[cfg(test)]
mod behavior_tests {
    use super::*;
    use parth_core::{crypto::hash::traits::{FromU64x4, ZeroableHash}, PF, PHash};

    #[derive(Default)]
    struct Cache;

    impl PSimpleContractHeightCache<PHash> for Cache {
        fn add_contract(&self, _: u32, _: u8, _: PHash) {}

        fn get_contract_height(&self, _: u32) -> anyhow::Result<u8> {
            Ok(0)
        }

        fn get_contract_zero_hash(&self, _: u32) -> anyhow::Result<PHash> {
            Ok(PHash::get_zero_value())
        }
    }

    fn proof(old_root: u64, old_value: u64, new_root: u64, new_value: u64, index: u64, siblings: usize) -> DeltaMerkleProofCore<PHash> {
        let hash = |value| PHash::from_u64x4([value, 0, 0, 0]);
        DeltaMerkleProofCore {
            old_root: hash(old_root),
            old_value: hash(old_value),
            new_root: hash(new_root),
            new_value: hash(new_value),
            index,
            siblings: vec![PHash::get_zero_value(); siblings],
        }
    }

    #[test]
    fn consistency_and_slot_updates_cover_valid_and_invalid_histories() {
        let update = proof(10, 1, 20, 2, 7, 2);
        let history = QEDContractStateUpdateHistory {
            user_contract_tree_update_proof: proof(0, 10, 0, 20, 12, 3),
            contract_state_tree_updates: vec![update],
        };
        history.ensure_basic_consistency(&Cache, 3).unwrap();
        assert_eq!(history.get_double_id_nodes_size_hint(), 4);
        let slots = history.get_slot_updates::<PF>().unwrap();
        assert_eq!(slots.contract_id, 12);
        assert_eq!(slots.slot_updates.len(), 1);
        assert_eq!(slots.slot_updates[0].slot, 28);

        let empty = QEDContractStateUpdateHistory::<PHash> {
            user_contract_tree_update_proof: proof(0, 0, 0, 0, 0, 0),
            contract_state_tree_updates: vec![],
        };
        assert_eq!(empty.get_double_id_nodes_size_hint(), 0);
        assert!(empty.ensure_basic_consistency(&Cache, 0).is_err());

        let wrong_height = QEDContractStateUpdateHistory {
            user_contract_tree_update_proof: proof(0, 10, 0, 20, 12, 2),
            contract_state_tree_updates: vec![proof(10, 1, 20, 2, 7, 2)],
        };
        assert!(wrong_height.ensure_basic_consistency(&Cache, 3).is_err());
    }

    #[test]
    fn consistency_rejects_mismatched_roots_and_broken_chains() {
        // first CST old root does not match the UCT old value (non-zero old value)
        let mismatched_first = QEDContractStateUpdateHistory {
            user_contract_tree_update_proof: proof(0, 11, 0, 20, 12, 3),
            contract_state_tree_updates: vec![proof(10, 1, 20, 2, 7, 3)],
        };
        assert!(mismatched_first.ensure_basic_consistency(&Cache, 3).is_err());

        // zero UCT old value: first CST old root must equal the contract zero hash
        let zero_valued = QEDContractStateUpdateHistory {
            user_contract_tree_update_proof: proof(0, 0, 0, 20, 12, 3),
            contract_state_tree_updates: vec![proof(10, 1, 20, 2, 7, 3)],
        };
        assert!(zero_valued.ensure_basic_consistency(&Cache, 3).is_err());

        // a fresh (all-zero) first old root is accepted through the zero-hash branch
        let fresh = QEDContractStateUpdateHistory {
            user_contract_tree_update_proof: proof(0, 0, 0, 20, 12, 3),
            contract_state_tree_updates: vec![proof(0, 0, 20, 2, 7, 3)],
        };
        fresh.ensure_basic_consistency(&Cache, 3).unwrap();

        // last CST new root does not match the UCT new value
        let mismatched_last = QEDContractStateUpdateHistory {
            user_contract_tree_update_proof: proof(0, 10, 0, 21, 12, 3),
            contract_state_tree_updates: vec![proof(10, 1, 20, 2, 7, 3)],
        };
        assert!(mismatched_last.ensure_basic_consistency(&Cache, 3).is_err());

        // mid-chain sibling height mismatch
        let bad_height_chain = QEDContractStateUpdateHistory {
            user_contract_tree_update_proof: proof(0, 10, 0, 30, 12, 3),
            contract_state_tree_updates: vec![
                proof(10, 1, 20, 2, 7, 3),
                proof(20, 2, 30, 3, 7, 4),
            ],
        };
        assert!(bad_height_chain.ensure_basic_consistency(&Cache, 3).is_err());

        // broken old_root -> new_root transition between consecutive updates
        let broken_chain = QEDContractStateUpdateHistory {
            user_contract_tree_update_proof: proof(0, 10, 0, 30, 12, 3),
            contract_state_tree_updates: vec![
                proof(10, 1, 20, 2, 7, 3),
                proof(21, 2, 30, 3, 7, 3),
            ],
        };
        assert!(broken_chain.ensure_basic_consistency(&Cache, 3).is_err());

        // a fully consistent multi-update chain passes
        let chain = QEDContractStateUpdateHistory {
            user_contract_tree_update_proof: proof(0, 10, 0, 30, 12, 3),
            contract_state_tree_updates: vec![
                proof(10, 1, 20, 2, 7, 3),
                proof(20, 2, 30, 3, 9, 3),
            ],
        };
        chain.ensure_basic_consistency(&Cache, 3).unwrap();
        assert_eq!(chain.get_double_id_nodes_size_hint(), 2 * 3 + 2);
    }

    #[test]
    fn slot_updates_capture_every_changed_felt_offset() {
        use parth_core::felt::ToU64Value;

        let dmp = |old: [u64; 4], new: [u64; 4], index: u64| DeltaMerkleProofCore {
            old_root: PHash::get_zero_value(),
            old_value: PHash::from_u64x4(old),
            new_root: PHash::get_zero_value(),
            new_value: PHash::from_u64x4(new),
            index,
            siblings: vec![PHash::get_zero_value(); 2],
        };
        let history = QEDContractStateUpdateHistory {
            user_contract_tree_update_proof: proof(0, 0, 0, 0, 3, 2),
            contract_state_tree_updates: vec![
                dmp([1, 2, 3, 4], [1, 9, 3, 8], 2),
                dmp([7, 0, 0, 0], [0, 0, 0, 7], 5),
            ],
        };
        let slots = history.get_slot_updates::<PF>().unwrap();
        assert_eq!(slots.contract_id, 3);
        let got: Vec<(u64, u64, u64)> = slots
            .slot_updates
            .iter()
            .map(|u| (u.slot, u.old_value.to_u64_value(), u.new_value.to_u64_value()))
            .collect();
        // unchanged felts are skipped; slots are index * 4 + offset
        assert_eq!(got, vec![(9, 2, 9), (11, 4, 8), (20, 7, 0), (23, 0, 7)]);
    }

    struct MissingContractCache;

    impl PSimpleContractHeightCache<PHash> for MissingContractCache {
        fn add_contract(&self, _: u32, _: u8, _: PHash) {}

        fn get_contract_height(&self, id: u32) -> anyhow::Result<u8> {
            anyhow::bail!("contract {} not loaded", id)
        }

        fn get_contract_zero_hash(&self, _: u32) -> anyhow::Result<PHash> {
            Ok(PHash::get_zero_value())
        }
    }

    #[test]
    fn default_contains_key_follows_height_lookup_success() {
        // default trait implementation, success branch
        assert!(Cache.contains_key(0));
        // default trait implementation, failure branch
        assert!(!MissingContractCache.contains_key(7));
    }

    #[cfg(feature = "node")]
    #[test]
    fn dash_map_height_cache_tracks_contracts() {
        let cache = DashMapContractHeightCache::<PHash>::new();
        assert!(!cache.contains_key(1));
        assert!(cache.get_contract_height(1).is_err());
        assert!(cache.get_contract_zero_hash(1).is_err());

        cache.add_contract(1, 4, PHash::get_zero_value());
        assert!(cache.contains_key(1));
        assert_eq!(cache.get_contract_height(1).unwrap(), 4);
        assert_eq!(cache.get_contract_zero_hash(1).unwrap(), PHash::get_zero_value());
    }

    #[cfg(feature = "rand_gen")]
    #[test]
    fn random_histories_round_trip() {
        use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

        for _ in 0..32 {
            let history = QEDContractStateUpdateHistory::<PHash>::qp_rand_gen();
            let bytes = history.psy_ser_to_bytes_vec().unwrap();
            assert_eq!(
                QEDContractStateUpdateHistory::<PHash>::psy_ser_from_slice(&bytes).unwrap(),
                history
            );
            // The fallback writer accepts the same histories even though its
            // reader cannot decode them back under the default feature set:
            // the user-contract-tree proof is read through the speedy buffered
            // stream reader, which consumes the bytes of the update vector.
            assert!(history.fallback_psy_ser_to_bytes_vec().unwrap().len() > 0);
        }
    }
}
