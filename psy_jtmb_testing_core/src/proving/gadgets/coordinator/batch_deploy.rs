use parth_core::{
    crypto::hash::{spiderman::SpidermanUpdateProof, traits::{FieldQHasher, QFieldHashable}}, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase}
};
use psy_data::v1::qdata::contract::PQEDContractLeafV2;
use crate::proving::{gadgets::coordinator::spiderman::verify_spiderman_append_proof, utils::connect::jtmb_connect_ref};

// Batch deploy logic connects spiderman new leaves to contract leaf hashes if added
pub fn verify_batch_deploy<Hash: Q256BitHash + QFHashBase<F>, F: QFelt64, Hasher: FieldQHasher<F, Hash>>(
    spiderman_proof: &SpidermanUpdateProof<Hash>,
    contract_ids: &[u64],
    contract_leaves: &[PQEDContractLeafV2<F, Hash>],
    contract_tree_height: usize,
    batch_sub_tree_height: usize,
) -> anyhow::Result<()> {
    let top_line_height = contract_tree_height
        .checked_sub(batch_sub_tree_height)
        .ok_or_else(|| anyhow::anyhow!("contract batch subtree exceeds contract tree height"))?;
    verify_spiderman_append_proof::<Hash, F, Hasher>(spiderman_proof, top_line_height, batch_sub_tree_height)?;

    let zero = Hash::get_zero_value();
    let window_size = spiderman_proof.web_proof_old_leaves.len();
    let window_start = spiderman_proof.top_line_proof.index
        .checked_mul(window_size as u64)
        .ok_or_else(|| anyhow::anyhow!("contract deploy window index overflow"))?;
    
    if contract_leaves.len() > spiderman_proof.web_proof_new_leaves.len() {
        anyhow::bail!("too many contract leaves for batch size");
    }

    let mut added_index = 0;
    for (i, (old, new)) in spiderman_proof.web_proof_old_leaves.iter().zip(spiderman_proof.web_proof_new_leaves.iter()).enumerate() {
        let is_added = *old == zero && *new != zero;
        
        if is_added {
            let contract_id = contract_ids.get(added_index)
                .ok_or_else(|| anyhow::anyhow!("missing contract id for added index {}", i))?;
            let expected_contract_id = window_start
                .checked_add(i as u64)
                .ok_or_else(|| anyhow::anyhow!("deployed contract id overflow"))?;
            anyhow::ensure!(
                *contract_id == expected_contract_id,
                "deployed contract id does not match proof position"
            );
            let contract_leaf = contract_leaves.get(added_index)
                .ok_or_else(|| anyhow::anyhow!("missing contract leaf input for added index {}", i))?;
            let leaf_hash = contract_leaf.qfhash::<Hasher>();
            jtmb_connect_ref(&leaf_hash, new, "contract leaf hash mismatch")?;
            added_index += 1;
        }
    }

    anyhow::ensure!(
        added_index == contract_ids.len() && added_index == contract_leaves.len(),
        "deploy vectors do not match added proof leaves"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_core::{
        crypto::hash::{
            merkle_proof::DeltaMerkleProofCore,
            traits::{MerkleLeafHasher, QFieldHashable},
            spiderman::SpidermanUpdateProof,
        },
        pgoldilocks::PoseidonHasher,
        PF, PHash,
    };
    use psy_data::v1::qdata::contract::PQEDContractLeafV2;

    fn proof(old_leaves: Vec<PHash>, new_leaves: Vec<PHash>) -> SpidermanUpdateProof<PHash> {
        SpidermanUpdateProof {
            top_line_proof: DeltaMerkleProofCore::from_params::<PoseidonHasher>(
                3,
                PoseidonHasher::compute_root_from_leaves(&old_leaves).unwrap(),
                PoseidonHasher::compute_root_from_leaves(&new_leaves).unwrap(),
                vec![PHash::default(); 2],
            ),
            web_proof_old_leaves: old_leaves,
            web_proof_new_leaves: new_leaves,
        }
    }

    fn added_contract_leaf() -> PQEDContractLeafV2<PF, PHash> {
        PQEDContractLeafV2 {
            code_root: PHash::from_values(1, 2, 3, 4),
            ..Default::default()
        }
    }

    #[test]
    fn batch_deploy_uses_compact_leaf_order_for_later_window_slot() {
        let existing_leaf_hash = PHash::from_values(4, 3, 2, 1);
        let added_leaf = added_contract_leaf();
        let old_leaves = vec![existing_leaf_hash, PHash::default()];
        let new_leaves = vec![
            existing_leaf_hash,
            added_leaf.qfhash::<PoseidonHasher>(),
        ];

        assert!(verify_batch_deploy::<PHash, PF, PoseidonHasher>(
            &proof(old_leaves, new_leaves),
            &[7],
            &[added_leaf],
            3,
            1,
        )
        .is_ok());
    }

    #[test]
    fn batch_deploy_rejects_missing_or_unused_contract_leaves() {
        let existing_leaf_hash = PHash::from_values(4, 3, 2, 1);
        let added_leaf = added_contract_leaf();
        let old_leaves = vec![existing_leaf_hash, PHash::default()];
        let new_leaves = vec![
            existing_leaf_hash,
            added_leaf.qfhash::<PoseidonHasher>(),
        ];
        let proof = proof(old_leaves, new_leaves);

        assert!(verify_batch_deploy::<PHash, PF, PoseidonHasher>(
            &proof,
            &[7],
            &[],
            3,
            1,
        )
        .unwrap_err()
        .to_string()
        .contains("missing contract leaf input for added index 1"));
        assert!(verify_batch_deploy::<PHash, PF, PoseidonHasher>(
            &proof,
            &[7, 8],
            &[added_leaf, added_leaf],
            3,
            1,
        )
        .unwrap_err()
        .to_string()
        .contains("deploy vectors do not match added proof leaves"));
        assert!(verify_batch_deploy::<PHash, PF, PoseidonHasher>(
            &proof,
            &[6],
            &[added_leaf],
            3,
            1,
        )
        .unwrap_err()
        .to_string()
        .contains("deployed contract id does not match proof position"));
    }
}
