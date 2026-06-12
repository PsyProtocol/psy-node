use kvq::traits::KVQSerializable;
use plonky2::util::{log2_ceil, log2_strict};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::core::{DeltaMerkleProofCore, MerkleProofCore};
use crate::hash::traits::hasher::{MerkleHasher, MerkleLeafHasher, ZeroableHash};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct SpidermanUpdateProof<Hash: PartialEq + Copy> {
    pub top_line_proof: DeltaMerkleProofCore<Hash>,
    pub web_proof_old_leaves: Vec<Hash>,
    pub web_proof_new_leaves: Vec<Hash>,
}

impl<Hash: PartialEq + Copy + ZeroableHash> SpidermanUpdateProof<Hash> {
    pub fn append_from_from_old_new_values<H: MerkleHasher<Hash>>(
        old_proof_to_inside: &MerkleProofCore<Hash>,
        existing_leaves: &[Hash],
        new_leaves: &[Hash],
        web_tree_height: usize,
    ) -> Self {
        let leaves_len = 1usize << web_tree_height;
        let mut web_proof_old_leaves = Vec::with_capacity(leaves_len);
        let zero_hashes_to_add = leaves_len - existing_leaves.len();

        web_proof_old_leaves.extend_from_slice(&existing_leaves);
        for _ in 0..zero_hashes_to_add {
            web_proof_old_leaves.push(Hash::get_zero_value());
        }

        let mut web_proof_new_leaves = Vec::with_capacity(leaves_len);
        let zero_hashes_to_add = leaves_len - (existing_leaves.len() + new_leaves.len());

        web_proof_new_leaves.extend_from_slice(&existing_leaves);
        web_proof_new_leaves.extend_from_slice(&new_leaves);
        for _ in 0..zero_hashes_to_add {
            web_proof_new_leaves.push(Hash::get_zero_value());
        }

        let full_tree_height = old_proof_to_inside.siblings.len();
        //let top_line_height = full_tree_height-web_tree_height;
        let siblings = old_proof_to_inside.siblings[(old_proof_to_inside.siblings.len() - full_tree_height)..].to_vec();

        let computed_old_web_root = H::compute_root_from_leaves(&web_proof_old_leaves).unwrap();
        let computed_new_web_root = H::compute_root_from_leaves(&web_proof_new_leaves).unwrap();

        let top_line_index = old_proof_to_inside.index >> (web_tree_height as u64);

        let top_line_proof = DeltaMerkleProofCore::from_params::<H>(top_line_index, computed_old_web_root, computed_new_web_root, siblings);

        Self {
            top_line_proof,
            web_proof_old_leaves,
            web_proof_new_leaves,
        }
    }
}
impl<Hash: PartialEq + Copy> SpidermanUpdateProof<Hash> {
    pub fn from_delta_merkle_proofs<H: MerkleHasher<Hash>>(delta_merkle_proofs: &[DeltaMerkleProofCore<Hash>]) -> Self {
        let leaves_len = delta_merkle_proofs.len();
        let web_tree_height = log2_strict(leaves_len);
        //let full_tree_height = delta_merkle_proofs[0].siblings.len();
        //let top_line_height = full_tree_height-web_tree_height;

        let old_leaves = delta_merkle_proofs.iter().map(|x| x.old_value).collect::<Vec<_>>();
        let new_leaves = delta_merkle_proofs.iter().map(|x| x.old_value).collect::<Vec<_>>();

        let computed_old_web_root = H::compute_root_from_leaves(&old_leaves).unwrap();
        let computed_new_web_root = H::compute_root_from_leaves(&new_leaves).unwrap();

        let top_line_index = delta_merkle_proofs[0].index >> (web_tree_height as u64);
        let top_line_proof = DeltaMerkleProofCore {
            old_root: delta_merkle_proofs[0].old_root,
            old_value: computed_old_web_root,
            new_root: delta_merkle_proofs.last().unwrap().new_root,
            new_value: computed_new_web_root,
            index: top_line_index,
            siblings: delta_merkle_proofs[0].siblings[web_tree_height..].to_vec(),
        };

        Self {
            top_line_proof,
            web_proof_old_leaves: old_leaves,
            web_proof_new_leaves: new_leaves,
        }
    }
    pub fn get_web_sub_tree_height(&self) -> usize {
        log2_strict(self.web_proof_new_leaves.len())
    }
    pub fn verify<H: MerkleHasher<Hash>>(&self) -> bool {
        let leaves_len = self.web_proof_new_leaves.len();
        if self.web_proof_old_leaves.len() == leaves_len && leaves_len == (1usize << log2_ceil(leaves_len)) && self.top_line_proof.verify::<H>() {
            let computed_old_web_root = H::compute_root_from_leaves(&self.web_proof_old_leaves).unwrap();
            if computed_old_web_root == self.top_line_proof.old_value {
                let computed_new_web_root = H::compute_root_from_leaves(&self.web_proof_new_leaves).unwrap();
                if computed_new_web_root == self.top_line_proof.new_value {
                    return true;
                }
            }
        }
        false
    }
}

impl<Hash: PartialEq + Copy + Serialize + DeserializeOwned> KVQSerializable for SpidermanUpdateProof<Hash> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}
