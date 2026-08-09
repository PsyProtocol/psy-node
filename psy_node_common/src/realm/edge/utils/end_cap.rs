use parth_core::{
    crypto::hash::traits::QFieldHashable,
    felt::QFelt64,
    protocol::core_types::{QDBHashBase, QFHashBase, QFHasherU64},
};
use psy_data::{
    proof_input::guta::end_cap_input::{ContractStateUpdate, SubmitUserEndCapNonProofInput},
    v1::qdata::contract::{serialize_imt_leaf_ffs_entry_v2, IMTContractStateUpdate},
};
use psy_node_core::qblob::{
    blob_type::{QBlobMerkleNodeTreeType, QBLOB_IMT_LEAF_ENTRY_SIZE},
    data_views::single_merkle_node_batch::QBlobSingleIdMerkleRecorder,
    structs::common::{blob_metadata_header::QBlobWriterContextMetadataHeader, tree_node_batch_header::QBlobMerkleTreeNodeBatchHeaderV1},
};

pub fn validate_end_cap_and_generate_node_data_for_edge<F: QFelt64, Hash: QDBHashBase + QFHashBase<F>, Hasher: QFHasherU64<F, Hash>>(
    context: &QBlobWriterContextMetadataHeader,
    user_id: u64,
    end_cap: &SubmitUserEndCapNonProofInput<F, Hash>,
) -> anyhow::Result<Vec<u8>> {
    if end_cap.contract_state_updates.is_empty() {
        anyhow::bail!("End cap must have at least one contract state update");
    }
    let user_contract_tree_height = end_cap.contract_state_updates[0].user_contract_tree_update_proof.siblings.len();
    let single_size_hint = end_cap.single_id_nodes_size_hint_in_nodes_modified(user_contract_tree_height);
    let double_size_hint = end_cap.double_id_nodes_size_hint_in_nodes_modified();
    let mut single_id_recorder = QBlobSingleIdMerkleRecorder::new_with_multi_size_hints_with_header(single_size_hint, double_size_hint);

    let mut next_uct_end_root = end_cap.contract_state_updates[end_cap.contract_state_updates.len() - 1]
        .user_contract_tree_update_proof
        .new_root;
    let null_hash = Hasher::get_zero_hash(0);

    for csu in end_cap.contract_state_updates.iter().rev() {
        if csu.updates.is_empty() {
            anyhow::bail!("Contract state updates cannot be empty");
        }

        let computed_end_root = single_id_recorder.record_and_compute_merkle_root_validate_delta_merkle_proof::<Hash, Hasher>(
            user_id,
            user_contract_tree_height as u8,
            &csu.user_contract_tree_update_proof,
        )?;
        if computed_end_root != next_uct_end_root {
            anyhow::bail!("Computed contract state update end root does not match expected end root");
        }
        if computed_end_root != csu.user_contract_tree_update_proof.new_root {
            anyhow::bail!("Computed contract state update new root does not match proof new root");
        }
        next_uct_end_root = csu.user_contract_tree_update_proof.old_root;

        let first_old = csu.updates.first().unwrap().old_root();
        if csu.user_contract_tree_update_proof.old_value != first_old {
            let first_height = match csu.updates.first().unwrap() {
                ContractStateUpdate::Positional { delta_proof } => delta_proof.siblings.len(),
                ContractStateUpdate::IMT { update } => match update {
                    IMTContractStateUpdate::Update { delta_proof, .. } => delta_proof.siblings.len(),
                    IMTContractStateUpdate::Insert {
                        predecessor_delta_proof,
                        ..
                    } => predecessor_delta_proof.siblings.len(),
                },
            };
            let contract_empty_zero_hash = Hasher::get_zero_hash(first_height);

            if csu.user_contract_tree_update_proof.old_value == null_hash && first_old == contract_empty_zero_hash {
                // allow this special case where we are updating from an empty
                // tree it means a user never tried the contract
                // before, and we initialize it to an empty merkle tree with the
                // correct height
            } else {
                anyhow::bail!("User contract tree update proof old value does not match first contract state tree update old root");
            }
        }

        let last_new = csu.updates.last().unwrap().new_root();
        if csu.user_contract_tree_update_proof.new_value != last_new {
            anyhow::bail!("User contract tree update proof new value does not match last contract state tree update new root");
        }
    }

    let mut double_id_recorder = single_id_recorder.finalize_with_header_into_double(&context, QBlobMerkleNodeTreeType::UserContractTree);
    let mut serialized_leaves = Vec::new();
    for csu in end_cap.contract_state_updates.iter().rev() {
        let contract_id = csu.user_contract_tree_update_proof.index;
        let mut next_cst_root = csu.updates.last().unwrap().new_root();
        for update in csu.updates.iter().rev() {
            match update {
                ContractStateUpdate::Positional { delta_proof } => {
                    let computed = double_id_recorder.record_and_compute_merkle_root_validate_delta_merkle_proof::<Hash, Hasher>(
                        user_id,
                        contract_id,
                        delta_proof.siblings.len() as u8,
                        delta_proof,
                    )?;
                    if computed != delta_proof.new_root || next_cst_root != delta_proof.new_root {
                        anyhow::bail!("Positional update root chain mismatch");
                    }
                    next_cst_root = delta_proof.old_root;
                }
                ContractStateUpdate::IMT { update } => match update {
                    IMTContractStateUpdate::Update {
                        new_preimage,
                        delta_proof,
                        ..
                    } => {
                        let computed = double_id_recorder.record_and_compute_merkle_root_validate_delta_merkle_proof::<Hash, Hasher>(
                            user_id,
                            contract_id,
                            delta_proof.siblings.len() as u8,
                            delta_proof,
                        )?;
                        if computed != delta_proof.new_root || next_cst_root != delta_proof.new_root {
                            tracing::info!("IMT update root chain mismatch: computed={}, delta_proof.new_root={}, next_cst_root={}",
                                serde_json::to_string(&computed).unwrap(),
                                serde_json::to_string(&delta_proof.new_root).unwrap(),
                                serde_json::to_string(&next_cst_root).unwrap()
                            );
                            anyhow::bail!("IMT update root chain mismatch");
                        }
                        next_cst_root = delta_proof.old_root;

                        let leaf_hash = new_preimage.qfhash::<Hasher>();
                        let next_index = new_preimage.next_index.to_u64_value();
                        let serialized = serialize_imt_leaf_ffs_entry_v2(
                            user_id,
                            contract_id,
                            delta_proof.index,
                            &leaf_hash,
                            &new_preimage.key,
                            &new_preimage.value,
                            &new_preimage.next_key,
                            next_index,
                            false,
                        );
                        serialized_leaves.extend_from_slice(&serialized);
                    }
                    IMTContractStateUpdate::Insert {
                        predecessor_new_preimage,
                        new_leaf_preimage,
                        predecessor_delta_proof,
                        new_leaf_delta_proof,
                        ..
                    } => {
                        let computed_new_leaf = double_id_recorder.record_and_compute_merkle_root_validate_delta_merkle_proof::<Hash, Hasher>(
                            user_id,
                            contract_id,
                            new_leaf_delta_proof.siblings.len() as u8,
                            new_leaf_delta_proof,
                        )?;
                        if computed_new_leaf != new_leaf_delta_proof.new_root || next_cst_root != new_leaf_delta_proof.new_root {
                            anyhow::bail!("IMT insert root chain mismatch at new leaf");
                        }

                        let computed_pred = double_id_recorder.record_and_compute_merkle_root_validate_delta_merkle_proof::<Hash, Hasher>(
                            user_id,
                            contract_id,
                            predecessor_delta_proof.siblings.len() as u8,
                            predecessor_delta_proof,
                        )?;
                        if computed_pred != predecessor_delta_proof.new_root
                            || predecessor_delta_proof.new_root != new_leaf_delta_proof.old_root
                        {
                            anyhow::bail!("IMT insert root chain mismatch at predecessor");
                        }
                        next_cst_root = predecessor_delta_proof.old_root;

                        let pred_leaf_hash = predecessor_new_preimage.qfhash::<Hasher>();
                        let pred_next_index = predecessor_new_preimage.next_index.to_u64_value();
                        let pred_serialized = serialize_imt_leaf_ffs_entry_v2(
                            user_id,
                            contract_id,
                            predecessor_delta_proof.index,
                            &pred_leaf_hash,
                            &predecessor_new_preimage.key,
                            &predecessor_new_preimage.value,
                            &predecessor_new_preimage.next_key,
                            pred_next_index,
                            false,
                        );
                        serialized_leaves.extend_from_slice(&pred_serialized);

                        let new_leaf_hash = new_leaf_preimage.qfhash::<Hasher>();
                        let new_next_index = new_leaf_preimage.next_index.to_u64_value();
                        let new_serialized = serialize_imt_leaf_ffs_entry_v2(
                            user_id,
                            contract_id,
                            new_leaf_delta_proof.index,
                            &new_leaf_hash,
                            &new_leaf_preimage.key,
                            &new_leaf_preimage.value,
                            &new_leaf_preimage.next_key,
                            new_next_index,
                            true,
                        );
                        serialized_leaves.extend_from_slice(&new_serialized);
                    }
                },
            }
        }
        if next_cst_root != csu.user_contract_tree_update_proof.old_value {
            if csu.user_contract_tree_update_proof.old_value == null_hash {
                let first_height = match csu.updates.first().unwrap() {
                    ContractStateUpdate::Positional { delta_proof } => delta_proof.siblings.len(),
                    ContractStateUpdate::IMT { update } => match update {
                        IMTContractStateUpdate::Update { delta_proof, .. } => delta_proof.siblings.len(),
                        IMTContractStateUpdate::Insert {
                            predecessor_delta_proof,
                            ..
                        } => predecessor_delta_proof.siblings.len(),
                    },
                };
                let contract_empty_zero_hash = Hasher::get_zero_hash(first_height);
                if next_cst_root == contract_empty_zero_hash {
                    // allow this special case where we are updating from an
                    // empty tree it means a user never
                    // tried the contract before, and we
                    // initialize it to an empty merkle tree with the
                    // correct height
                } else {
                    anyhow::bail!("Computed contract state tree update overall old root does not match expected old root, next_cst_root = {:?}, expected = {:?}", next_cst_root, csu.user_contract_tree_update_proof.old_value);
                }
            } else {
                anyhow::bail!(
                    "Computed contract state tree update overall old root does not match expected old root, next_cst_root = {:?}, expected = {:?}",
                    next_cst_root,
                    csu.user_contract_tree_update_proof.old_value
                );
            }
        }
    }

    let mut result = double_id_recorder.finalize_with_header(context);
    if !serialized_leaves.is_empty() {
        let imt_entry_count =
            (serialized_leaves.len() / QBLOB_IMT_LEAF_ENTRY_SIZE) as u64;
        let mut imt_header =
            QBlobMerkleTreeNodeBatchHeaderV1::new_imt_leaf_header_from_context(
                context,
                QBlobMerkleNodeTreeType::IMTContractStateLeaf,
            );
        imt_header.modify_for_final_count_and_size(
            QBLOB_IMT_LEAF_ENTRY_SIZE as u32,
            imt_entry_count,
        );
        result.extend_from_slice(&imt_header.to_bytes_fixed_size_array());
        result.extend_from_slice(&serialized_leaves);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use parth_common::memory_stores::mem_tree_v3::SimpleMemoryMerkleStoreV3;
    use parth_core::{
        crypto::hash::traits::{MerkleZeroHasher, QFieldHashable},
        felt::{QFelt64, ToU64Value},
        pgoldilocks::PoseidonHasher,
        protocol::core_types::{Q256BitHash, QFHashBase, QFHasherU64},
        utils::QPGenRandom,
        PHash,
    };
    use psy_data::{
        guta::stats::GUTAStats,
        proof_input::guta::{
            end_cap_input::{ContractStateUpdate, ContractStateUpdateHistory, SubmitUserEndCapNonProofInput},
            SubmitUserEndCapNonProofCoreInput,
        },
        v1::qdata::{
            contract::{DashMapContractHeightCache, PSimpleContractHeightCache},
            user::PQEDUserLeaf,
            user_end_cap_result::PUPSEndCapResultCompact,
        },
    };
    use psy_node_core::qblob::{
        blob_type::QBlobMerkleNodeTreeType,
        data_views::{double_merkle_node_batch::QBlobDoubleMerkleNodeBatchDataView, single_merkle_node_batch::QBlobSingleMerkleNodeBatchDataView},
        structs::common::blob_metadata_header::QBlobWriterContextMetadataHeader,
    };

    use crate::realm::edge::utils::end_cap::validate_end_cap_and_generate_node_data_for_edge;

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
        Hash: Q256BitHash + QFHashBase<F> + QPGenRandom,
        Hasher: QFHasherU64<F, Hash> + MerkleZeroHasher<Hash>,
    {
        let mut user_contract_tree = SimpleMemoryMerkleStoreV3::<Hasher, Hash>::new(contract_tree_height);
        let contract_helper = DashMapContractHeightCache::new();

        let mut contract_trees = (0..5)
            .map(|i| {
                let contract_state_tree_height = 24 + i as u8;
                let tree = SimpleMemoryMerkleStoreV3::<Hasher, Hash>::new(contract_state_tree_height);
                //let max_leaf_id = 1u64 << contract_state_tree_height;
                contract_helper.add_contract(i as u32, contract_state_tree_height, tree.get_root());

                /*
                for _ in 0..1000 {
                    let rand_leaf_id = rand::random::<u64>() % max_leaf_id;
                    //tree.set_leaf(rand_leaf_id, Hash::qp_rand_gen());
                }*/
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
            contract_state_updates.push(ContractStateUpdateHistory {
                user_contract_tree_update_proof,
                updates: contract_state_tree_updates
                    .into_iter()
                    .map(|delta_proof| ContractStateUpdate::Positional { delta_proof })
                    .collect(),
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
            guta_fees_collected: F::from_owned_u64(1000),
            da_fees_collected: F::from_owned_u64(1000 * 50 * contract_trees.len() as u64),
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
            events: vec![],
        };

        let public_inputs_hash = input.core.get_proof_public_inputs_hash::<Hasher>(global_user_tree_height);
        input
            .ensure_simple_self_consistent::<Hasher, _>(
                &old_user_leaf,
                public_inputs_hash,
                &contract_helper,
                global_user_tree_height,
                contract_tree_height as usize,
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
    #[test]
    fn test_input_group() -> anyhow::Result<()> {
        let global_user_tree_height = 32u8;
        let contract_tree_height = 24u8;
        type Hash = PHash;
        type F = parth_core::PF;
        type Hasher = PoseidonHasher;
        let (old_user_leaf, end_cap, contract_helper) =
            gen_fake_valid_submit_user_end_cap_non_proof_input::<F, Hash, Hasher>(global_user_tree_height, contract_tree_height);

        let proof_public_inputs_hash = end_cap.core.get_proof_public_inputs_hash::<Hasher>(global_user_tree_height);

        assert!(end_cap
            .ensure_simple_self_consistent::<Hasher, _>(
                &old_user_leaf,
                proof_public_inputs_hash,
                &contract_helper,
                global_user_tree_height,
                contract_tree_height as usize
            )
            .is_ok());
        let user_id = old_user_leaf.user_id.to_u64_value();

        let context = QBlobWriterContextMetadataHeader::new_at_now(0, 1, 2, 3, 4, 2000, user_id);

        let res = validate_end_cap_and_generate_node_data_for_edge::<F, Hash, Hasher>(&context, user_id, &end_cap)?;

        let (_single_header, single_payload, double_full) =
            QBlobSingleMerkleNodeBatchDataView::validate_single_tree_nodes_batch_header_for_realm_context_get_clipped_ref_no_exact_size(
                &res,
                context.chain_id,
                context.realm_id,
                context.realm_sub_id,
                context.unique_pending_id,
                QBlobMerkleNodeTreeType::UserContractTree,
            )?;
        let (_double_header, double_payload) = QBlobDoubleMerkleNodeBatchDataView::validate_uct_nodes_batch_header_for_realm_context_get_clipped_ref(
            &double_full,
            context.chain_id,
            context.realm_id,
            context.realm_sub_id,
            context.unique_pending_id,
        )?;

        let single_nodes = QBlobSingleMerkleNodeBatchDataView::read_batch_single_nodes_from_checked_payload::<Hash>(single_payload)?;

        let single_leaf_nodes = single_nodes
            .iter()
            .filter(|x| x.key.level == contract_tree_height)
            .map(|x| *x)
            .collect::<Vec<_>>();
        let _single_leaf_hashes = single_leaf_nodes.iter().map(|x| x.value).collect::<Vec<_>>();
        assert_eq!(single_leaf_nodes.len(), end_cap.contract_state_updates.len());

        let double_nodes = QBlobDoubleMerkleNodeBatchDataView::read_batch_double_nodes_from_checked_payload::<Hash>(double_payload)?;
        println!("double_nodes_len {}", double_nodes.len());

        Ok(())
    }
}
