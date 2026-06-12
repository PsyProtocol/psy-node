use hashbrown::HashSet;
use kvq::traits::KVQSerializable;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::common::SimpleMerkleNodeKey;
use crate::hash::{merkle::core::DeltaMerkleProofCore, traits::hasher::MerkleZeroHasherWithMarkedLeaf};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UpdateNearestCommonAncestorProof<Hash: PartialEq + Copy> {
    pub old_nearest_common_ancestor_value: Hash,
    pub new_nearest_common_ancestor_value: Hash,

    pub child_a: DeltaMerkleProofCore<Hash>,
    pub child_b: DeltaMerkleProofCore<Hash>,

    pub nearest_common_ancestor_level: u8,
    pub nearest_common_ancestor_index: u64,

    pub level_a: u8,
    pub level_b: u8,
}

impl<Hash: PartialEq + Copy + Serialize + DeserializeOwned> KVQSerializable for UpdateNearestCommonAncestorProof<Hash> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}
impl<Hash: PartialEq + Copy> UpdateNearestCommonAncestorProof<Hash> {
    pub fn to_partial(&self) -> PartialUpdateNearestCommonAncestorProof<Hash> {
        PartialUpdateNearestCommonAncestorProof {
            child_a: self.child_a.clone(),
            child_b: self.child_b.clone(),
            nearest_common_ancestor_level: self.nearest_common_ancestor_level,
        }
    }
}

impl<Hash: PartialEq + Copy> From<UpdateNearestCommonAncestorProof<Hash>> for PartialUpdateNearestCommonAncestorProof<Hash> {
    fn from(value: UpdateNearestCommonAncestorProof<Hash>) -> Self {
        PartialUpdateNearestCommonAncestorProof {
            child_a: value.child_a,
            child_b: value.child_b,
            nearest_common_ancestor_level: value.nearest_common_ancestor_level,
        }
    }
}

impl<Hash: PartialEq + Copy> From<&UpdateNearestCommonAncestorProof<Hash>> for PartialUpdateNearestCommonAncestorProof<Hash> {
    fn from(value: &UpdateNearestCommonAncestorProof<Hash>) -> Self {
        PartialUpdateNearestCommonAncestorProof {
            child_a: value.child_a.clone(),
            child_b: value.child_b.clone(),
            nearest_common_ancestor_level: value.nearest_common_ancestor_level,
        }
    }
}

impl<Hash: PartialEq + Copy> UpdateNearestCommonAncestorProof<Hash> {
    pub fn get_a_node_key(&self) -> SimpleMerkleNodeKey {
        SimpleMerkleNodeKey {
            level: self.level_a,
            index: self.child_a.index,
        }
    }
    pub fn get_b_node_key(&self) -> SimpleMerkleNodeKey {
        SimpleMerkleNodeKey {
            level: self.level_b,
            index: self.child_b.index,
        }
    }
    pub fn is_solo_filler(&self) -> bool {
        self.child_a.new_root == self.child_b.new_root && self.child_a.eq(&self.child_b)
    }
    pub fn verify<H: MerkleZeroHasherWithMarkedLeaf<Hash>>(&self) -> bool {
        let solo_mask = !self.is_solo_filler() as u8;
        if self.level_a == (self.nearest_common_ancestor_level + (self.child_a.siblings.len() as u8) + solo_mask)
            && self.level_b == (self.nearest_common_ancestor_level + (self.child_b.siblings.len() as u8) + solo_mask)
        {
            let level_diff_a = self.level_a - self.nearest_common_ancestor_level;
            let level_diff_b = self.level_b - self.nearest_common_ancestor_level;

            let nca_index_a = self.child_a.index >> (level_diff_a as u64);
            let nca_index_b = self.child_b.index >> (level_diff_b as u64);
            if nca_index_a == nca_index_b
                && nca_index_a == self.nearest_common_ancestor_index
                && self.child_a.verify::<H>()
                && self.child_b.verify::<H>()
            {
                let is_a_right = self.get_a_node_key().is_on_the_right_of(&self.get_b_node_key());

                let computed_old_root = if is_a_right {
                    H::two_to_one(&self.child_b.old_root, &self.child_a.old_root)
                } else {
                    H::two_to_one(&self.child_a.old_root, &self.child_b.old_root)
                };
                let computed_new_root = if is_a_right {
                    H::two_to_one(&self.child_b.new_root, &self.child_a.new_root)
                } else {
                    H::two_to_one(&self.child_a.new_root, &self.child_b.new_root)
                };

                return self.old_nearest_common_ancestor_value == computed_old_root && self.new_nearest_common_ancestor_value == computed_new_root;
            }
        }

        false
    }
    pub fn validate<H: MerkleZeroHasherWithMarkedLeaf<Hash>>(&self) {
        assert_eq!(
            self.level_a,
            self.nearest_common_ancestor_level + (self.child_a.siblings.len() as u8) + 1,
            "invalid level_a in UpdateNearestCommonAncestorProof"
        );
        assert_eq!(
            self.level_b,
            self.nearest_common_ancestor_level + (self.child_b.siblings.len() as u8) + 1,
            "invalid level_a in UpdateNearestCommonAncestorProof"
        );
        assert!(
            self.level_a > self.nearest_common_ancestor_level,
            "level_a must be greater than nearest_common_ancestor_level"
        );
        assert!(
            self.level_b > self.nearest_common_ancestor_level,
            "level_b must be greater than nearest_common_ancestor_level"
        );

        let level_diff_a = self.level_a - self.nearest_common_ancestor_level;
        let level_diff_b = self.level_b - self.nearest_common_ancestor_level;

        let nca_index_a = self.child_a.index >> (level_diff_a as u64);
        let nca_index_b = self.child_b.index >> (level_diff_b as u64);

        assert_eq!(nca_index_a, nca_index_b, "the children must agree on the nearest common ancestor index");
        assert_eq!(
            nca_index_a, self.nearest_common_ancestor_index,
            "the children must with the nearest common ancestor index"
        );

        assert!(self.child_a.verify::<H>(), "child a is invalid");
        assert!(self.child_b.verify::<H>(), "child b is invalid");
        let is_a_right = self.get_a_node_key().is_on_the_right_of(&self.get_b_node_key());

        let computed_old_root = if is_a_right {
            H::two_to_one(&self.child_b.old_root, &self.child_a.old_root)
        } else {
            H::two_to_one(&self.child_a.old_root, &self.child_b.old_root)
        };
        let computed_new_root = if is_a_right {
            H::two_to_one(&self.child_b.new_root, &self.child_a.new_root)
        } else {
            H::two_to_one(&self.child_a.new_root, &self.child_b.new_root)
        };

        assert!(
            self.old_nearest_common_ancestor_value == computed_old_root,
            "old_nearest_common_ancestor_value is incorrect"
        );
        assert!(
            self.new_nearest_common_ancestor_value == computed_new_root,
            "new_nearest_common_ancestor_value is incorrect"
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NCAProofsWithTopLine<Hash: PartialEq + Copy> {
    pub nca_proofs: Vec<UpdateNCAWithAdditionalLink<Hash>>,
    pub top_line_proof: DeltaMerkleProofCore<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PartialNCAProofsWithTopLine<Hash: PartialEq + Copy> {
    pub nca_proofs: Vec<PartialUpdateNearestCommonAncestorProof<Hash>>,
    pub top_line_proof: DeltaMerkleProofCore<Hash>,
}

impl<Hash: PartialEq + Copy + Serialize + DeserializeOwned> KVQSerializable for PartialNCAProofsWithTopLine<Hash> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PartialUpdateNearestCommonAncestorProof<Hash: PartialEq + Copy> {
    pub child_a: DeltaMerkleProofCore<Hash>,
    pub child_b: DeltaMerkleProofCore<Hash>,

    pub nearest_common_ancestor_level: u8,
}

impl<Hash: PartialEq + Copy + Serialize + DeserializeOwned> KVQSerializable for PartialUpdateNearestCommonAncestorProof<Hash> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<Hash: PartialEq + Copy> PartialUpdateNearestCommonAncestorProof<Hash> {
    pub fn get_level_a(&self) -> u8 {
        self.nearest_common_ancestor_level + (self.child_a.siblings.len() as u8) + 1
    }
    pub fn get_level_b(&self) -> u8 {
        self.nearest_common_ancestor_level + (self.child_b.siblings.len() as u8) + 1
    }
    pub fn get_a_node_key(&self) -> SimpleMerkleNodeKey {
        SimpleMerkleNodeKey {
            level: self.get_level_a(),
            index: self.child_a.index,
        }
    }
    pub fn get_b_node_key(&self) -> SimpleMerkleNodeKey {
        SimpleMerkleNodeKey {
            level: self.get_level_b(),
            index: self.child_b.index,
        }
    }
    pub fn compute_old_nca_value<H: MerkleZeroHasherWithMarkedLeaf<Hash>>(&self) -> Hash {
        let is_a_right = self.get_a_node_key().is_on_the_right_of(&self.get_b_node_key());

        if is_a_right {
            H::two_to_one(&self.child_b.old_root, &self.child_a.old_root)
        } else {
            H::two_to_one(&self.child_a.old_root, &self.child_b.old_root)
        }
    }
    pub fn compute_new_nca_value<H: MerkleZeroHasherWithMarkedLeaf<Hash>>(&self) -> Hash {
        let is_a_right = self.get_a_node_key().is_on_the_right_of(&self.get_b_node_key());

        if is_a_right {
            H::two_to_one(&self.child_b.new_root, &self.child_a.new_root)
        } else {
            H::two_to_one(&self.child_a.new_root, &self.child_b.new_root)
        }
    }
    pub fn get_nca_index(&self) -> u64 {
        let level_diff_a = self.get_level_a() - self.nearest_common_ancestor_level;
        //let level_diff_b = self.get_level_b() - self.nearest_common_ancestor_level;
        self.child_a.index >> (level_diff_a as u64)
    }
    pub fn into_full_proof<H: MerkleZeroHasherWithMarkedLeaf<Hash>>(self) -> UpdateNearestCommonAncestorProof<Hash> {
        let old_nearest_common_ancestor_value = self.compute_old_nca_value::<H>();
        let new_nearest_common_ancestor_value = self.compute_new_nca_value::<H>();
        UpdateNearestCommonAncestorProof {
            old_nearest_common_ancestor_value,
            new_nearest_common_ancestor_value,
            nearest_common_ancestor_level: self.nearest_common_ancestor_level,
            level_a: self.get_level_a(),
            level_b: self.get_level_b(),
            nearest_common_ancestor_index: self.get_nca_index(),
            child_a: self.child_a,
            child_b: self.child_b,
        }
    }
    pub fn to_full_proof<H: MerkleZeroHasherWithMarkedLeaf<Hash>>(&self) -> UpdateNearestCommonAncestorProof<Hash> {
        let old_nearest_common_ancestor_value = self.compute_old_nca_value::<H>();
        let new_nearest_common_ancestor_value = self.compute_new_nca_value::<H>();
        UpdateNearestCommonAncestorProof {
            old_nearest_common_ancestor_value,
            new_nearest_common_ancestor_value,
            child_a: self.child_a.clone(),
            child_b: self.child_b.clone(),
            nearest_common_ancestor_level: self.nearest_common_ancestor_level,
            level_a: self.get_level_a(),
            level_b: self.get_level_b(),
            nearest_common_ancestor_index: self.get_nca_index(),
        }
    }
}

impl<Hash: PartialEq + Copy> PartialUpdateNearestCommonAncestorProof<Hash> {
    pub fn from_delta_merkle_proof_pair<H: MerkleZeroHasherWithMarkedLeaf<Hash>>(
        dmp_a: &DeltaMerkleProofCore<Hash>,
        dmp_b: &DeltaMerkleProofCore<Hash>,
    ) -> Self {
        let height = dmp_a.siblings.len() as u8;
        assert_eq!(
            dmp_a.siblings.len(),
            dmp_b.siblings.len(),
            "from_delta_merkle_proof_pair requires valid delta merkle proofs to the same root"
        );
        assert!(dmp_a.index != dmp_b.index, "delta merkle proofs must be different");

        let leaf_key_a = SimpleMerkleNodeKey::new(height, dmp_a.index);
        let leaf_key_b = SimpleMerkleNodeKey::new(height, dmp_b.index);

        // nearest_common_ancestor.level is at most (height-1)
        let nearest_common_ancestor = leaf_key_a.find_nearest_common_ancestor(&leaf_key_b);

        // dist_to_nca is at least 1
        let dist_to_nca = (height - nearest_common_ancestor.level) as usize;

        Self {
            nearest_common_ancestor_level: nearest_common_ancestor.level,
            child_a: dmp_a.shorten_height::<H>(dist_to_nca - 1),
            child_b: dmp_b.shorten_height::<H>(dist_to_nca - 1),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PartialUpdateNCAWithAdditionalLink<Hash: PartialEq + Copy> {
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<Hash>,
    pub link_siblings: Vec<Hash>,
}
impl<Hash: PartialEq + Copy + Serialize + DeserializeOwned> KVQSerializable for PartialUpdateNCAWithAdditionalLink<Hash> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<Hash: PartialEq + Copy> PartialUpdateNCAWithAdditionalLink<Hash> {
    pub fn from_delta_merkle_proof_pair<H: MerkleZeroHasherWithMarkedLeaf<Hash>>(
        dmp_a: &DeltaMerkleProofCore<Hash>,
        dmp_b: &DeltaMerkleProofCore<Hash>,
    ) -> Self {
        let height = dmp_a.siblings.len() as u8;
        assert_eq!(
            dmp_a.siblings.len(),
            dmp_b.siblings.len(),
            "from_delta_merkle_proof_pair requires valid delta merkle proofs to the same root"
        );
        assert!(dmp_a.index != dmp_b.index, "delta merkle proofs must be different");

        let leaf_key_a = SimpleMerkleNodeKey::new(height, dmp_a.index);
        let leaf_key_b = SimpleMerkleNodeKey::new(height, dmp_b.index);
        let nearest_common_ancestor = leaf_key_a.find_nearest_common_ancestor(&leaf_key_b);

        let dist_to_nca = (height - nearest_common_ancestor.level) as usize;
        let link_siblings = dmp_a.siblings[dist_to_nca..].to_vec();
        assert!(
            link_siblings.eq(&dmp_b.siblings[dist_to_nca..]),
            "from_delta_merkle_proof_pair requires valid delta merkle proofs to the same root"
        );

        Self {
            nca_proof: PartialUpdateNearestCommonAncestorProof {
                nearest_common_ancestor_level: nearest_common_ancestor.level,
                child_a: dmp_a.shorten_height::<H>(dist_to_nca - 1),
                child_b: dmp_b.shorten_height::<H>(dist_to_nca - 1),
            },
            link_siblings,
        }
    }
    pub fn from_delta_merkle_proof_pair_alt_height<H: MerkleZeroHasherWithMarkedLeaf<Hash>>(
        dmp_a: &DeltaMerkleProofCore<Hash>,
        dmp_b: &DeltaMerkleProofCore<Hash>,
    ) -> Self {
        let height_a = dmp_a.siblings.len() as u8;
        let height_b = dmp_a.siblings.len() as u8;

        let leaf_key_a = SimpleMerkleNodeKey::new(height_a, dmp_a.index);
        let leaf_key_b = SimpleMerkleNodeKey::new(height_b, dmp_b.index);
        assert!(leaf_key_a != leaf_key_b, "delta merkle proofs must be different");
        assert!(
            !leaf_key_a.is_direct_path_related(&leaf_key_b),
            "delta merkle proofs cannot be on the same path"
        );
        let nearest_common_ancestor = leaf_key_a.find_nearest_common_ancestor(&leaf_key_b);

        let dist_to_nca_a = (height_a - nearest_common_ancestor.level) as usize;
        let dist_to_nca_b = (height_b - nearest_common_ancestor.level) as usize;
        let link_siblings = dmp_a.siblings[dist_to_nca_a..].to_vec();
        assert!(
            link_siblings.eq(&dmp_b.siblings[dist_to_nca_b..]),
            "from_delta_merkle_proof_pair requires valid delta merkle proofs to the same root"
        );

        Self {
            nca_proof: PartialUpdateNearestCommonAncestorProof {
                nearest_common_ancestor_level: nearest_common_ancestor.level,
                child_a: dmp_a.shorten_height::<H>(dist_to_nca_a - 1),
                child_b: dmp_b.shorten_height::<H>(dist_to_nca_b - 1),
            },
            link_siblings,
        }
    }
    pub fn to_full_proof<H: MerkleZeroHasherWithMarkedLeaf<Hash>>(&self) -> UpdateNCAWithAdditionalLink<Hash> {
        let nca_proof = self.nca_proof.to_full_proof::<H>();
        let link_proof = DeltaMerkleProofCore::from_params::<H>(
            nca_proof.nearest_common_ancestor_index,
            nca_proof.old_nearest_common_ancestor_value,
            nca_proof.new_nearest_common_ancestor_value,
            self.link_siblings.clone(),
        );
        UpdateNCAWithAdditionalLink { nca_proof, link_proof }
    }
    pub fn into_full_proof<H: MerkleZeroHasherWithMarkedLeaf<Hash>>(self) -> UpdateNCAWithAdditionalLink<Hash> {
        let nca_proof = self.nca_proof.into_full_proof::<H>();
        let link_proof = DeltaMerkleProofCore::from_params::<H>(
            nca_proof.nearest_common_ancestor_index,
            nca_proof.old_nearest_common_ancestor_value,
            nca_proof.new_nearest_common_ancestor_value,
            self.link_siblings,
        );
        UpdateNCAWithAdditionalLink { nca_proof, link_proof }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UpdateNCAWithAdditionalLink<Hash: PartialEq + Copy> {
    pub nca_proof: UpdateNearestCommonAncestorProof<Hash>,
    pub link_proof: DeltaMerkleProofCore<Hash>,
}

impl<Hash: PartialEq + Copy> UpdateNCAWithAdditionalLink<Hash> {
    pub fn from_delta_merkle_proof_pair<H: MerkleZeroHasherWithMarkedLeaf<Hash>>(
        dmp_a: &DeltaMerkleProofCore<Hash>,
        dmp_b: &DeltaMerkleProofCore<Hash>,
    ) -> Self {
        PartialUpdateNCAWithAdditionalLink::from_delta_merkle_proof_pair::<H>(dmp_a, dmp_b).to_full_proof::<H>()
    }
    pub fn to_partial_proof(&self) -> PartialUpdateNCAWithAdditionalLink<Hash> {
        PartialUpdateNCAWithAdditionalLink {
            nca_proof: PartialUpdateNearestCommonAncestorProof {
                child_a: self.nca_proof.child_a.clone(),
                child_b: self.nca_proof.child_b.clone(),
                nearest_common_ancestor_level: self.nca_proof.nearest_common_ancestor_level,
            },
            link_siblings: self.link_proof.siblings.clone(),
        }
    }
    pub fn into_partial_proof(self) -> PartialUpdateNCAWithAdditionalLink<Hash> {
        PartialUpdateNCAWithAdditionalLink {
            nca_proof: PartialUpdateNearestCommonAncestorProof {
                child_a: self.nca_proof.child_a,
                child_b: self.nca_proof.child_b,
                nearest_common_ancestor_level: self.nca_proof.nearest_common_ancestor_level,
            },
            link_siblings: self.link_proof.siblings,
        }
    }
    pub fn verify<H: MerkleZeroHasherWithMarkedLeaf<Hash>>(&self) -> bool {
        self.nca_proof.verify::<H>()
            && self.link_proof.verify::<H>()
            && self.nca_proof.old_nearest_common_ancestor_value == self.link_proof.old_value
            && self.nca_proof.new_nearest_common_ancestor_value == self.link_proof.new_value
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct UpdateNCAProofsWithDependencies<Hash: PartialEq + Copy> {
    pub nca_proofs: Vec<UpdateNearestCommonAncestorProof<Hash>>,
    //pub levels: Vec<usize>,
    pub dependencies: Vec<(i64, i64)>,
    pub root_proof_index: usize,

    pub nearest_common_ancestor_level: u8,
    pub nearest_common_ancestor_index: u64,

    pub link_level: u8,
    pub link_index: u64,
    pub link_proof: DeltaMerkleProofCore<Hash>,
}
impl<Hash: PartialEq + Copy + Default> UpdateNCAProofsWithDependencies<Hash> {
    pub fn new() -> Self {
        Self::default()
    }
}
impl<Hash: PartialEq + Copy + Default> UpdateNCAProofsWithDependencies<Hash> {
    pub fn get_index_levels(&self) -> Vec<Vec<usize>> {
        let mut solved = HashSet::<i64>::new();

        let total_values = self.nca_proofs.len();
        let mut solved_values = 0;
        let mut remaining = (0..total_values).collect::<Vec<_>>();

        let mut levels = Vec::new();
        while solved_values < total_values {
            let mut new_remaining = Vec::new();
            let mut level = Vec::new();

            for x in remaining {
                let (l, r) = self.dependencies[x];
                if (l <= -1 || solved.contains(&l)) && (r <= -1 || solved.contains(&r)) {
                    level.push(x);
                    solved_values += 1;
                } else {
                    new_remaining.push(x);
                }
            }
            for i in level.iter() {
                solved.insert(*i as i64);
            }
            remaining = new_remaining;
            levels.push(level);
        }

        levels
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BinaryXWithDependencyLevels<T> {
    pub data: Vec<T>,
    pub levels: Vec<usize>,
    pub dependencies: Vec<(i64, i64)>,
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use plonky2::field::goldilocks_field::GoldilocksField;
    use psy_client_common::data::qhashout::QHashOut;
    use rand::{thread_rng, Rng, RngCore};

    use super::{PartialUpdateNCAWithAdditionalLink, UpdateNCAWithAdditionalLink};
    use crate::hash::{
        merkle::utils::{common::SimpleMerkleNodeKey, simple_merkle_tree::SimpleMerkleTree},
        traits::hasher::{MerkleZeroHasherWithMarkedLeaf, PoseidonHasher},
    };

    type F = GoldilocksField;
    type PsyHash = QHashOut<F>;
    type H = PoseidonHasher;

    fn _rand_leaf_node_key<Hasher: MerkleZeroHasherWithMarkedLeaf<Hash>, Hash: Copy + PartialEq + Default + Debug>(
        tree: &SimpleMerkleTree<Hasher, Hash>,
    ) -> SimpleMerkleNodeKey {
        let index = thread_rng().gen::<u64>() & tree.get_max_leaf_index();
        SimpleMerkleNodeKey {
            level: tree.get_height(),
            index,
        }
    }
    fn rand_leaf_pair_no_collisions(tree_height: u8) -> (SimpleMerkleNodeKey, SimpleMerkleNodeKey) {
        let max_node_index = (1u64 << (tree_height as u64)) - 1u64;

        if tree_height == 1 {
            (
                SimpleMerkleNodeKey {
                    level: tree_height,
                    index: 0,
                },
                SimpleMerkleNodeKey {
                    level: tree_height,
                    index: 1,
                },
            )
        } else {
            let a = SimpleMerkleNodeKey {
                level: tree_height,
                index: thread_rng().gen::<u64>() & max_node_index,
            };

            let mut b = SimpleMerkleNodeKey {
                level: tree_height,
                index: thread_rng().gen::<u64>() & max_node_index,
            };
            while a.eq(&b) {
                b = SimpleMerkleNodeKey {
                    level: tree_height,
                    index: thread_rng().gen::<u64>() & max_node_index,
                };
            }
            (a, b)
        }
    }
    fn _rand_leaves_no_collisions(tree_height: u8, count: usize) -> Vec<SimpleMerkleNodeKey> {
        let max_node_index = (1u64 << (tree_height as u64)) - 1u64;
        let max_leaves = (max_node_index + 1) as usize;
        if count == max_leaves {
            return (0..(max_leaves as u64))
                .map(|i| SimpleMerkleNodeKey {
                    level: tree_height,
                    index: i,
                })
                .collect::<Vec<_>>();
        }
        let inds = if count > max_leaves {
            panic!("tried to generate {} unique leaf indicies for a tree of height {}", count, tree_height);
        } else if count < 100 || count < (max_leaves - count) {
            let mut existing_inds = Vec::with_capacity(count);
            let mut found = 0;
            while found < count {
                let v = thread_rng().next_u64() & max_node_index;
                if !existing_inds.contains(&v) {
                    found += 1;
                    existing_inds.push(v);
                }
            }
            existing_inds
        } else {
            // find the leaves that are not in here
            let comp_size = max_leaves - count;
            let mut existing_inds = Vec::with_capacity(comp_size);
            let mut found = 0;
            while found < count {
                let v = thread_rng().next_u64() & max_node_index;
                if !existing_inds.contains(&v) {
                    found += 1;
                    existing_inds.push(v);
                }
            }
            let mut results = Vec::with_capacity(count);
            let c64 = count as u64;
            for index in 0..c64 {
                if !existing_inds.contains(&index) {
                    results.push(index)
                }
            }
            results
        };

        inds.into_iter()
            .map(|index| SimpleMerkleNodeKey { level: tree_height, index })
            .collect::<Vec<_>>()
    }

    fn gen_random_update_nca_with_additioanl_link_for_tree(tree: &mut SimpleMerkleTree<H, PsyHash>) -> UpdateNCAWithAdditionalLink<PsyHash> {
        let (leaf_a, leaf_b) = rand_leaf_pair_no_collisions(tree.get_height());

        let dmp_a = tree.set_leaf(leaf_a.index, QHashOut::rand());
        let dmp_b = tree.set_leaf(leaf_b.index, QHashOut::rand());

        UpdateNCAWithAdditionalLink::from_delta_merkle_proof_pair::<H>(&dmp_a, &dmp_b)
    }
    /*
    pub fn generate_partial_nca_proof_multi_level_b(
        tree: &mut SimpleMerkleTree<H, PsyHash>,
    ) -> PartialUpdateNearestCommonAncestorProof<QHashOut<F>> {
        let (leaf_a, leaf_b) = rand_leaf_pair_no_collisions(tree.get_height());

        let dmp_a = tree.set_leaf(leaf_a.index, QHashOut::rand());
        let dmp_b = tree.set_leaf(leaf_b.index, QHashOut::rand());

        let mut base = PartialUpdateNearestCommonAncestorProof::from_delta_merkle_proof_pair::<H>(
            &dmp_a, &dmp_b,
        );

        let base_height = base.child_a.siblings.len() as u8;
        if base_height > 2 {
            let new_height_a = (thread_rng().gen::<u8>() % (base_height + 1)) as usize;
            let new_height_b = (thread_rng().gen::<u8>() % base_height) as usize + 1;

            base.child_a = base
                .child_a
                .with_shortened_height_from_bottom::<H>(new_height_a);
            base.child_b = base
                .child_b
                .with_shortened_height_from_bottom::<H>(new_height_b);
        }
        base
    }*/

    pub fn generate_nca_proof_multi_level_link(tree: &mut SimpleMerkleTree<H, PsyHash>) -> UpdateNCAWithAdditionalLink<QHashOut<F>> {
        let (leaf_a, leaf_b) = rand_leaf_pair_no_collisions(tree.get_height());

        let dmp_a = tree.set_leaf(leaf_a.index, QHashOut::rand());
        let dmp_b = tree.set_leaf(leaf_b.index, QHashOut::rand());

        let mut base = PartialUpdateNCAWithAdditionalLink::from_delta_merkle_proof_pair::<H>(&dmp_a, &dmp_b);

        let base_height = base.nca_proof.child_a.siblings.len() as u8;
        if base_height > 2 {
            let new_height_a = (thread_rng().gen::<u8>() % (base_height + 1)) as usize;
            let new_height_b = (thread_rng().gen::<u8>() % base_height) as usize + 1;

            base.nca_proof.child_a = base.nca_proof.child_a.with_shortened_height_from_bottom::<H>(new_height_a);
            base.nca_proof.child_b = base.nca_proof.child_b.with_shortened_height_from_bottom::<H>(new_height_b);
        }
        base.into_full_proof::<H>()
    }

    #[test]
    fn test_verify_nca_proof() {
        let mut tree = SimpleMerkleTree::<H, PsyHash>::new(32);

        for _ in 0..500 {
            let random_proof_0 = gen_random_update_nca_with_additioanl_link_for_tree(&mut tree);
            assert!(random_proof_0.verify::<H>(), "random nca proof is not valid");
        }
    }
    #[test]
    fn test_verify_nca_proof_multi_level() {
        for h in 1..32 {
            let mut tree = SimpleMerkleTree::<H, PsyHash>::new(h);

            for _ in 0..50 {
                let random_proof_0 = generate_nca_proof_multi_level_link(&mut tree);
                //println!("rp:
                // {}",serde_json::to_string_pretty(&random_proof_0.to_full_proof::<H>()).
                // unwrap());
                assert!(random_proof_0.verify::<H>(), "random nca proof is not valid");
            }
        }
    }
}
