use parth_core::{
    crypto::hash::traits::{FieldQHasher, QFieldHashable},
    felt::QFelt64,
    protocol::core_types::QFHashBase,
};

use crate::{
    proof_input::guta::SubmitUserEndCapNonProofCoreInput,
    v1::qdata::{
        contract::{PSimpleContractHeightCache, QEDContractStateUpdateHistory},
        user::PQEDUserLeaf,
    },
};

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct SubmitUserEndCapNonProofInput<F, Hash> {
    pub core: SubmitUserEndCapNonProofCoreInput<F, Hash>,
    pub contract_state_updates: Vec<QEDContractStateUpdateHistory<Hash>>,
}

impl<F: QFelt64, Hash: QFHashBase<F> + std::fmt::Debug> SubmitUserEndCapNonProofInput<F, Hash> {
    pub fn ensure_simple_self_consistent<Hasher: FieldQHasher<F, Hash>, C: PSimpleContractHeightCache<Hash>>(
        &self,
        old_user_leaf: &PQEDUserLeaf<F, Hash>,
        proof_public_inputs_hash: Hash,
        contract_helper: &C,
        global_user_tree_height: u8,
        contract_tree_height: usize,
    ) -> anyhow::Result<()> {
        if self.core.checkpoint_id != self.core.new_user_leaf.last_checkpoint_id {
            anyhow::bail!(
                "invalid checkpoint id, left: {}, right: {}",
                self.core.checkpoint_id,
                self.core.new_user_leaf.last_checkpoint_id
            );
        }
        if self.core.new_user_leaf.user_id != self.core.state_transition.user_id {
            anyhow::bail!(
                "inconsistent user id, left: {}, right: {}",
                self.core.new_user_leaf.user_id,
                self.core.state_transition.user_id
            );
        }

        let expected_proof_public_inputs_hash = self.core.get_proof_public_inputs_hash::<Hasher>(global_user_tree_height);
        if proof_public_inputs_hash != expected_proof_public_inputs_hash {
            anyhow::bail!(
                "invalid public inputs/state transition, left: {:?}, right: {:?}",
                proof_public_inputs_hash,
                expected_proof_public_inputs_hash
            );
        }
        let old_leaf_hash = old_user_leaf.qfhash::<Hasher>();
        if old_leaf_hash != self.core.state_transition.start_user_leaf_hash {
            anyhow::bail!("invalid old_user_leaf");
        }
        if old_user_leaf.last_checkpoint_id.to_u64_value() >= self.core.checkpoint_id.to_u64_value() {
            anyhow::bail!(
                "old_user_leaf last_checkpoint_id {} is not less than end cap checkpoint_id {}",
                old_user_leaf.last_checkpoint_id.to_u64_value(),
                self.core.checkpoint_id
            );
        }

        let computed_leaf_hash = self.core.new_user_leaf.qfhash::<Hasher>();
        if computed_leaf_hash != self.core.state_transition.end_user_leaf_hash {
            anyhow::bail!("invalid new_user_leaf");
        }
        if self.contract_state_updates.len() == 0 {
            anyhow::bail!("contract_state_updates cannot be empty");
        }

        for i in 1..self.contract_state_updates.len() {
            if self.contract_state_updates[i - 1].user_contract_tree_update_proof.new_root
                != self.contract_state_updates[i].user_contract_tree_update_proof.old_root
            {
                anyhow::bail!(
                    "contract_state_updates are not consistent at index {}, left: {:?}, right: {:?}",
                    i,
                    self.contract_state_updates[i - 1].user_contract_tree_update_proof.new_root,
                    self.contract_state_updates[i].user_contract_tree_update_proof.old_root
                );
            }
        }

        let csu_old_root = self
            .contract_state_updates
            .first()
            .as_ref()
            .unwrap()
            .user_contract_tree_update_proof
            .old_root;

        if csu_old_root != old_user_leaf.user_state_tree_root {
            anyhow::bail!(
                "user_state_tree_root does not match the first old root, left: {:?}, right: {:?}",
                csu_old_root,
                old_user_leaf.user_state_tree_root
            );
        }
        let csu_last_new_root = self
            .contract_state_updates
            .last()
            .as_ref()
            .unwrap()
            .user_contract_tree_update_proof
            .new_root;

        if csu_last_new_root != self.core.new_user_leaf.user_state_tree_root {
            anyhow::bail!(
                "user_state_tree_root does not match the last new root, left: {:?}, right: {:?}",
                csu_last_new_root,
                self.core.new_user_leaf.user_state_tree_root
            );
        }

        for csu in self.contract_state_updates.iter() {
            csu.ensure_basic_consistency(contract_helper, contract_tree_height)?;
        }

        Ok(())
    }
    pub fn get_needed_contract_zero_hashes(&self) -> Vec<(u64, usize)> {
        self.contract_state_updates
            .iter()
            .filter_map(|x| {
                if x.user_contract_tree_update_proof.old_value == Hash::get_zero_value() && x.contract_state_tree_updates.len() != 0 {
                    Some((x.user_contract_tree_update_proof.index, x.contract_state_tree_updates[0].siblings.len()))
                } else {
                    None
                }
            })
            .collect()
    }
    pub fn single_id_nodes_size_hint_in_nodes_modified(&self, contract_tree_height: usize) -> usize {
        self.contract_state_updates.len() * (1 + contract_tree_height) + 1
    }
    pub fn double_id_nodes_size_hint_in_nodes_modified(&self) -> usize {
        let mut count = 0;
        for csu in self.contract_state_updates.iter() {
            count += csu.get_double_id_nodes_size_hint();
        }
        count
    }
    /*
    pub fn verify_and_generate_cst_updates<H: FieldQHasher<F, Hash>>(&self, checkpoint_id: u64, old_user_state_tree_root: Hash) -> anyhow::Result<CSTUserUpdate<Hash>> {

        if self.contract_state_updates.len() == 0 {
            anyhow::bail!("contract_state_updates cannot be empty");
        }


        if self.contract_state_updates[0].user_contract_tree_update_proof.old_root != old_user_state_tree_root {

            anyhow::bail!("old_user_state_tree_root does not match the first old root ({:?}, {:?})",self.contract_state_updates[0].user_contract_tree_update_proof.old_root,old_user_state_tree_root);
        }
        let mut injestor = CSTUserUpdateStore::<Hash>::new();

        for csu in self.contract_state_updates.iter() {
            csu.verify_generate_cst_delta::<H>(&mut injestor)?;
        }

        let upd = injestor.into_updates(checkpoint_id, self.core.state_transition.user_id.to_canonical_u64());



        Ok(upd)
    }
    */
}

#[cfg(test)]
pub mod gen_fake_data {
    use parth_common::memory_stores::mem_tree_v3::SimpleMemoryMerkleStoreV3;
    use parth_core::{
        crypto::hash::traits::{MerkleZeroHasher, QFieldHashable},
        felt::QFelt64,
        protocol::core_types::{QFHashBase, QFHasherU64},
        utils::QPGenRandom,
    };

    use crate::{
        guta::stats::GUTAStats,
        proof_input::guta::{end_cap_input::SubmitUserEndCapNonProofInput, SubmitUserEndCapNonProofCoreInput},
        v1::qdata::{
            contract::{DashMapContractHeightCache, PSimpleContractHeightCache, QEDContractStateUpdateHistory},
            user::PQEDUserLeaf,
            user_end_cap_result::PUPSEndCapResultCompact,
        },
    };

    pub fn gen_fake_valid_submit_user_end_cap_non_proof_input<F, Hash, Hasher>(
        global_user_tree_height: u8,
        contract_tree_height: u8,
    ) -> (
        PQEDUserLeaf<F, Hash>,
        SubmitUserEndCapNonProofInput<F, Hash>,
        DashMapContractHeightCache<Hash>,
    )
    where
        F: QFelt64,
        Hash: QFHashBase<F> + QPGenRandom,
        Hasher: QFHasherU64<F, Hash> + MerkleZeroHasher<Hash>,
    {
        let mut user_contract_tree = SimpleMemoryMerkleStoreV3::<Hasher, Hash>::new(contract_tree_height);
        let contract_helper = DashMapContractHeightCache::new();

        let mut contract_trees = (0..5)
            .map(|i| {
                let contract_state_tree_height = 24 + i as u8;
                let mut tree = SimpleMemoryMerkleStoreV3::<Hasher, Hash>::new(contract_state_tree_height);
                let max_leaf_id = 1u64 << contract_state_tree_height;
                contract_helper.add_contract(0, contract_state_tree_height, tree.get_root());

                for _ in 0..1000 {
                    let rand_leaf_id = rand::random::<u64>() % max_leaf_id;
                    tree.set_leaf(rand_leaf_id, Hash::qp_rand_gen());
                }
                user_contract_tree.set_leaf(i as u64, tree.get_root());
                tree
            })
            .collect::<Vec<_>>();
        let old_user_contract_tree_root = user_contract_tree.get_root();
        let user_id = 42u64;
        let user_id_f = F::from_owned_u64(user_id);
        let old_checkpoint_id = 7u64;
        let old_checkpoint_id_f = F::from_owned_u64(old_checkpoint_id);

        let new_checkpoint_id = old_checkpoint_id + 1000;
        let new_checkpoint_id_f = F::from_owned_u64(new_checkpoint_id);

        let public_key = Hash::qp_rand_gen();
        let balance = F::from_owned_u64(1_000_000);
        let old_nonce = F::from_owned_u64(55);
        let event_index = F::from_owned_u64(1234);

        let old_user_leaf = PQEDUserLeaf {
            user_id: user_id_f,
            last_checkpoint_id: old_checkpoint_id_f,
            user_state_tree_root: old_user_contract_tree_root,
            public_key,
            balance,
            nonce: old_nonce,
            event_index,
        };
        let start_user_leaf_hash = old_user_leaf.qfhash::<Hasher>();

        let mut contract_state_updates = vec![];
        contract_trees.iter_mut().enumerate().for_each(|(i, ctree)| {
            let leaf_count = ctree.get_max_leaf_index() + 1;
            let contract_state_tree_updates = (0..50)
                .map(|_| {
                    let rand_leaf_id = rand::random::<u64>() % leaf_count;
                    ctree.set_leaf(rand_leaf_id, Hash::qp_rand_gen())
                })
                .collect::<Vec<_>>();
            let end_root = ctree.get_root();
            let user_contract_tree_update_proof = user_contract_tree.set_leaf(i as u64, end_root);
            contract_state_updates.push(QEDContractStateUpdateHistory {
                user_contract_tree_update_proof,
                contract_state_tree_updates,
            });
        });

        let new_user_contract_tree_root = user_contract_tree.get_root();
        let new_user_leaf = PQEDUserLeaf {
            user_id: user_id_f,
            last_checkpoint_id: new_checkpoint_id_f,
            user_state_tree_root: new_user_contract_tree_root,
            public_key,
            balance,
            nonce: F::from_owned_u64(56),
            event_index: F::from_owned_u64(1235),
        };
        let end_user_leaf_hash = new_user_leaf.qfhash::<Hasher>();

        let new_checkpoint_tree_root = Hash::qp_rand_gen();
        let state_transition = PUPSEndCapResultCompact {
            start_user_leaf_hash,
            end_user_leaf_hash,
            checkpoint_tree_root_hash: new_checkpoint_tree_root,
            user_id: user_id_f,
        };

        let guta_stats = GUTAStats {
            fees_collected: F::from_owned_u64(1000),
            user_ops_processed: F::from_owned_u64(1),
            total_transactions: F::from_owned_u64(contract_trees.len() as u64),
            slots_modified: F::from_owned_u64(50 * contract_trees.len() as u64),
        };

        let core = SubmitUserEndCapNonProofCoreInput {
            checkpoint_id: new_checkpoint_id_f,
            state_transition,
            new_user_leaf,
            stats: guta_stats,
        };

        let input = SubmitUserEndCapNonProofInput {
            core,
            contract_state_updates,
        };

        let public_inputs_hash = input.core.get_proof_public_inputs_hash::<Hasher>(global_user_tree_height);
        input
            .ensure_simple_self_consistent::<Hasher, _>(
                &old_user_leaf,
                public_inputs_hash,
                &contract_helper,
                global_user_tree_height,
                contract_tree_height as usize
            )
            .unwrap();
        assert!(input
            .ensure_simple_self_consistent::<Hasher, _>(
                &old_user_leaf,
                public_inputs_hash,
                &contract_helper,
                global_user_tree_height,
                contract_tree_height as usize
            )
            .is_ok());

        (old_user_leaf, input, contract_helper)
    }
}


#[cfg(test)]
mod tests {
    use parth_core::{pgoldilocks::PoseidonHasher, PHash};

    use crate::proof_input::guta::end_cap_input::gen_fake_data::{gen_fake_valid_submit_user_end_cap_non_proof_input};


    #[test]
    fn generate_simple_input() {
        type Hash = PHash;
        type F = parth_core::PF;
        type Hasher = PoseidonHasher;
        let (old_user_leaf, input, contract_helper) = gen_fake_valid_submit_user_end_cap_non_proof_input::<F, Hash, Hasher>(32, 30);

        let proof_public_inputs_hash = input.core.get_proof_public_inputs_hash::<Hasher>(32);

        assert!(input.ensure_simple_self_consistent::<Hasher, _>(&old_user_leaf, proof_public_inputs_hash, &contract_helper, 32, 30).is_ok());




    }
}