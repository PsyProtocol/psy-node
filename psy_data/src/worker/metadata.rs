use parth_core::{
    QJOB_ID_SERIALIZED_SIZE, QJobIdBase, crypto::hash::{tag_tree::{TagTreeStorageNode, hash_tag_tree_node, hash_tag_tree_node_four, hash_tag_tree_node_three}, traits::{MerkleHasher, ZeroableHash}}, data::hash::merkle_node_key::SimpleMerkleNodeKey, protocol::core_types::Q256BitHash, utils::QPGenRandom
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata};

pub const PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD: u8 = 0;
pub const PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN: u8 = 1;
pub const PROOF_REWARD_TREE_HASH_MODE_3_CHILDREN_DOUBLE_REWARD: u8 = 2;
pub const PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD: u8 = 3;
pub const PROOF_REWARD_TREE_HASH_MODE_4_CHILDREN: u8 = 4;

#[pderive::serialize_clone_hash_job_id_ts]
#[ts(export, concrete(Hash = parth_core::PHash, JobId = QProvingJobDataID))]
#[repr(C)]
pub struct PsyProvingJobMetadata<Hash, JobId> {
    pub expected_public_inputs_hash: Hash,
    pub reward_tree_node_index: u64,
    pub reward_tree_node_level: u8,
    pub reward_tree_hash_mode: u8,      // How to hash this node's children when computing the reward tree hash
    pub reward_tree_node_children: u16, // Number of children this node has in the reward tree, used to hint at how to hash
    pub dependencies: Vec<JobId>,
}

impl<Hash: Default, JobId: Default> Default for PsyProvingJobMetadata<Hash, JobId> {
    fn default() -> Self {
        Self {
            expected_public_inputs_hash: Hash::default(),
            reward_tree_node_index: 0,
            reward_tree_node_level: 0,
            reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN,
            reward_tree_node_children: 0,
            dependencies: Vec::new(),
        }
    }
}

impl<Hash, JobId> PsyProvingJobMetadata<Hash, JobId> {
    pub fn get_reward_tree_node_key(&self) -> SimpleMerkleNodeKey {
        SimpleMerkleNodeKey {
            index: self.reward_tree_node_index,
            level: self.reward_tree_node_level,
        }
    }
}
impl<Hash: ZeroableHash + Copy, JobId> PsyProvingJobMetadata<Hash, JobId> {

    pub fn get_new_rewards_tag_tree_value<Hasher: MerkleHasher<Hash>>(&self, tag: Hash, children: &[Hash]) -> anyhow::Result<Hash> {
        let res = match self.reward_tree_hash_mode {
            PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN => {
                let zero = Hash::get_zero_value();
                hash_tag_tree_node::<Hash, Hasher>(&zero, &zero, &tag)
            }
            PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD => {
                if children.len() != 2 {
                    anyhow::bail!("Expected 2 children for standard hash mode, got {}", children.len());
                }
                hash_tag_tree_node::<Hash, Hasher>(&children[0], &children[1], &tag)
            }
            PROOF_REWARD_TREE_HASH_MODE_3_CHILDREN_DOUBLE_REWARD => {
                if children.len() != 3 {
                    anyhow::bail!("Expected 3 children for 3-children double reward hash mode, got {}", children.len());
                }
                hash_tag_tree_node_three::<Hash, Hasher>(&children[0], &children[1], &children[2], &tag)
            }
            PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD => {
                if children.len() == 0 {
                    anyhow::bail!("Expected at least 1 child for lift child hash mode, got 0");
                }
                hash_tag_tree_node::<Hash, Hasher>(&children[0], &Hash::get_zero_value(), &tag)
            }
            PROOF_REWARD_TREE_HASH_MODE_4_CHILDREN => {
                if children.len() != 4 {
                    anyhow::bail!("Expected 4 children for 4-children reward hash mode, got {}", children.len());
                }
                hash_tag_tree_node_four::<Hash, Hasher>(&children[0], &children[1], &children[2], &children[3], &tag)
            }
            _ => anyhow::bail!("Unknown reward tree hash mode: {}", self.reward_tree_hash_mode),
        };
        Ok(res)
    }
    pub fn compute_reward_tagged_expected_public_inputs<Hasher: MerkleHasher<Hash>>(&self, tag: Hash, children_reward_tree_values: &[Hash]) -> anyhow::Result<Hash> {
        let reward_tree_value = self.get_new_rewards_tag_tree_value::<Hasher>(tag, children_reward_tree_values)?;
        Ok(Hasher::two_to_one(&self.expected_public_inputs_hash, &reward_tree_value))
    }
}
impl<Hash: ZeroableHash + Copy + PartialEq, JobId> PsyProvingJobMetadata<Hash, JobId> {

    pub fn get_new_rewards_tag_tree_updates<Hasher: MerkleHasher<Hash>>(&self, tag: Hash, children_reward_tree_values: &[Hash], reward_tree_value: Hash) -> anyhow::Result<Vec<(SimpleMerkleNodeKey, TagTreeStorageNode<Hash>)>>{
        let mut updates = Vec::new();
        if self.reward_tree_hash_mode == PROOF_REWARD_TREE_HASH_MODE_3_CHILDREN_DOUBLE_REWARD {
            // special case for 3 children
            if self.dependencies.len() != 3 || children_reward_tree_values.len() != 3 {
                anyhow::bail!(
                    "Expected 3 children for 3-children double reward hash mode, got {}",
                    self.dependencies.len()
                );
            }

            let last_two = hash_tag_tree_node::<Hash, Hasher>(&children_reward_tree_values[1], &children_reward_tree_values[2], &tag);
            let top_value = hash_tag_tree_node::<Hash, Hasher>(&children_reward_tree_values[0], &last_two, &tag);
            if top_value != reward_tree_value {
                anyhow::bail!("Computed top value does not match reward tree value for 3-children double reward hash mode");
            }
            let self_key = self.get_reward_tree_node_key();
            let right_key = self_key.right_child();

            updates.push((self_key, TagTreeStorageNode {
                tag,
                value: top_value,
            }));
            updates.push((right_key, TagTreeStorageNode {
                tag,
                value: last_two,
            }));
        } else if self.reward_tree_hash_mode == PROOF_REWARD_TREE_HASH_MODE_4_CHILDREN {
            // special case for 4 children: the children are laid out as
            // [c0, [c1, [c2, c3]]] under this node
            if self.dependencies.len() != 4 || children_reward_tree_values.len() != 4 {
                anyhow::bail!(
                    "Expected 4 children for 4-children reward hash mode, got {}",
                    self.dependencies.len()
                );
            }

            let last_two = hash_tag_tree_node::<Hash, Hasher>(&children_reward_tree_values[2], &children_reward_tree_values[3], &tag);
            let last_three = hash_tag_tree_node::<Hash, Hasher>(&children_reward_tree_values[1], &last_two, &tag);
            let top_value = hash_tag_tree_node::<Hash, Hasher>(&children_reward_tree_values[0], &last_three, &tag);
            if top_value != reward_tree_value {
                anyhow::bail!("Computed top value does not match reward tree value for 4-children reward hash mode");
            }
            let self_key = self.get_reward_tree_node_key();
            let right_key = self_key.right_child();
            let right_right_key = right_key.right_child();

            updates.push((self_key, TagTreeStorageNode {
                tag,
                value: top_value,
            }));
            updates.push((right_key, TagTreeStorageNode {
                tag,
                value: last_three,
            }));
            updates.push((right_right_key, TagTreeStorageNode {
                tag,
                value: last_two,
            }));
        } else if self.reward_tree_hash_mode == PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD {
            if children_reward_tree_values.len() < 1 {
                anyhow::bail!("Expected at least 1 child for lift child hash mode, got {}", children_reward_tree_values.len());
            }
            let self_key = self.get_reward_tree_node_key();
            let computed_reward_tree_value = self.get_new_rewards_tag_tree_value::<Hasher>(tag, &children_reward_tree_values[0..1])?;
            if computed_reward_tree_value != reward_tree_value {
                anyhow::bail!("Computed reward tree value does not match provided reward tree value");
            }
            updates.push((self_key, TagTreeStorageNode {
                tag,
                value: reward_tree_value,
            }));

        } else {
            let self_key = self.get_reward_tree_node_key();
            let computed_reward_tree_value = self.get_new_rewards_tag_tree_value::<Hasher>(tag, children_reward_tree_values)?;
            if computed_reward_tree_value != reward_tree_value {
                anyhow::bail!("Computed reward tree value does not match provided reward tree value");
            }
            updates.push((self_key, TagTreeStorageNode {
                tag,
                value: reward_tree_value,
            }));
        }

        Ok(updates)
    }
}

#[cfg(test)]
mod reward_behavior_tests {
    use parth_core::pgoldilocks::{PoseidonHasher, QHashOut};
    use parth_core::PF;

    use super::*;

    type Hash = QHashOut<PF>;

    fn hash(value: u64) -> Hash {
        Hash::from_values(value, 0, 0, 0)
    }

    fn metadata(mode: u8, dependencies: usize) -> PsyProvingJobMetadata<Hash, u8> {
        PsyProvingJobMetadata {
            expected_public_inputs_hash: hash(50),
            reward_tree_node_index: 3,
            reward_tree_node_level: 2,
            reward_tree_hash_mode: mode,
            reward_tree_node_children: dependencies as u16,
            dependencies: (0..dependencies as u8).collect(),
        }
    }

    #[test]
    fn reward_modes_accept_expected_children_and_reject_wrong_shapes() {
        let tag = hash(9);
        let cases = [
            (PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN, vec![]),
            (PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD, vec![hash(1), hash(2)]),
            (PROOF_REWARD_TREE_HASH_MODE_3_CHILDREN_DOUBLE_REWARD, vec![hash(1), hash(2), hash(3)]),
            (PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD, vec![hash(1)]),
            (PROOF_REWARD_TREE_HASH_MODE_4_CHILDREN, vec![hash(1), hash(2), hash(3), hash(4)]),
        ];
        for (mode, children) in cases {
            let value = metadata(mode, children.len());
            let reward = value.get_new_rewards_tag_tree_value::<PoseidonHasher>(tag, &children).unwrap();
            assert_ne!(reward, Hash::default());
            assert_ne!(value.compute_reward_tagged_expected_public_inputs::<PoseidonHasher>(tag, &children).unwrap(), reward);
            assert!(!value.get_new_rewards_tag_tree_updates::<PoseidonHasher>(tag, &children, reward).unwrap().is_empty());
        }

        assert!(metadata(PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD, 0)
            .get_new_rewards_tag_tree_value::<PoseidonHasher>(tag, &[]).is_err());
        assert!(metadata(PROOF_REWARD_TREE_HASH_MODE_3_CHILDREN_DOUBLE_REWARD, 2)
            .get_new_rewards_tag_tree_value::<PoseidonHasher>(tag, &[hash(1), hash(2)]).is_err());
        assert!(metadata(PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD, 0)
            .get_new_rewards_tag_tree_value::<PoseidonHasher>(tag, &[]).is_err());
        assert!(metadata(PROOF_REWARD_TREE_HASH_MODE_4_CHILDREN, 3)
            .get_new_rewards_tag_tree_value::<PoseidonHasher>(tag, &[hash(1), hash(2), hash(3)]).is_err());
        assert!(metadata(255, 0).get_new_rewards_tag_tree_value::<PoseidonHasher>(tag, &[]).is_err());
    }

    #[test]
    fn reward_updates_validate_dependency_counts_and_expected_value() {
        let tag = hash(9);
        let children3 = [hash(1), hash(2), hash(3)];
        let mode3 = metadata(PROOF_REWARD_TREE_HASH_MODE_3_CHILDREN_DOUBLE_REWARD, 3);
        let reward3 = mode3.get_new_rewards_tag_tree_value::<PoseidonHasher>(tag, &children3).unwrap();
        let updates3 = mode3.get_new_rewards_tag_tree_updates::<PoseidonHasher>(tag, &children3, reward3).unwrap();
        assert_eq!(updates3.len(), 2);
        assert_eq!(updates3[0].0, mode3.get_reward_tree_node_key());
        assert!(mode3.get_new_rewards_tag_tree_updates::<PoseidonHasher>(tag, &children3[..2], reward3).is_err());
        assert!(mode3.get_new_rewards_tag_tree_updates::<PoseidonHasher>(tag, &children3, hash(99)).is_err());

        let children4 = [hash(1), hash(2), hash(3), hash(4)];
        let mode4 = metadata(PROOF_REWARD_TREE_HASH_MODE_4_CHILDREN, 4);
        let reward4 = mode4.get_new_rewards_tag_tree_value::<PoseidonHasher>(tag, &children4).unwrap();
        assert_eq!(mode4.get_new_rewards_tag_tree_updates::<PoseidonHasher>(tag, &children4, reward4).unwrap().len(), 3);
        assert!(mode4.get_new_rewards_tag_tree_updates::<PoseidonHasher>(tag, &children4[..3], reward4).is_err());
        assert!(mode4.get_new_rewards_tag_tree_updates::<PoseidonHasher>(tag, &children4, hash(99)).is_err());

        let standard = metadata(PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD, 2);
        let children2 = [hash(1), hash(2)];
        let reward2 = standard.get_new_rewards_tag_tree_value::<PoseidonHasher>(tag, &children2).unwrap();
        assert!(standard.get_new_rewards_tag_tree_updates::<PoseidonHasher>(tag, &children2, hash(99)).is_err());
        assert_eq!(standard.get_new_rewards_tag_tree_updates::<PoseidonHasher>(tag, &children2, reward2).unwrap().len(), 1);
    }

    #[test]
    fn default_metadata_is_a_no_hash_children_leaf() {
        let value = PsyProvingJobMetadata::<Hash, u8>::default();
        assert_eq!(value.expected_public_inputs_hash, Hash::default());
        assert_eq!(value.reward_tree_node_index, 0);
        assert_eq!(value.reward_tree_node_level, 0);
        assert_eq!(value.reward_tree_hash_mode, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN);
        assert_eq!(value.reward_tree_node_children, 0);
        assert!(value.dependencies.is_empty());
        assert_eq!(value.get_reward_tree_node_key(), SimpleMerkleNodeKey { level: 0, index: 0 });
    }

    #[test]
    fn constructors_install_reward_key_and_hash_mode() {
        let key = SimpleMerkleNodeKey { level: 3, index: 12 };
        let pi_hash = hash(77);

        let leaf = PsyProvingJobMetadata::<Hash, u8>::new_leaf(pi_hash, key, vec![1, 2]);
        assert_eq!(leaf.expected_public_inputs_hash, pi_hash);
        assert_eq!(leaf.reward_tree_hash_mode, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN);
        assert_eq!(leaf.reward_tree_node_children, 0);
        assert_eq!(leaf.get_reward_tree_node_key(), key);
        assert_eq!(leaf.dependencies, vec![1u8, 2u8]);

        let inner = PsyProvingJobMetadata::<Hash, u8>::new_inner_standard(pi_hash, key, vec![1, 2]);
        assert_eq!(inner.reward_tree_hash_mode, PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD);
        assert_eq!(inner.reward_tree_node_children, 2);
        assert_eq!(inner.get_reward_tree_node_key(), key);
        assert_eq!(inner.dependencies, vec![1u8, 2u8]);

        let double = PsyProvingJobMetadata::<Hash, u8>::new_3_to_1_double_reward(pi_hash, key, vec![1, 2, 3]);
        assert_eq!(double.reward_tree_hash_mode, PROOF_REWARD_TREE_HASH_MODE_3_CHILDREN_DOUBLE_REWARD);
        assert_eq!(double.reward_tree_node_children, 3);
        assert_eq!(double.get_reward_tree_node_key(), key);
        assert_eq!(double.dependencies, vec![1u8, 2u8, 3u8]);

        let custom = PsyProvingJobMetadata::<Hash, u8>::new(pi_hash, 21, 9, PROOF_REWARD_TREE_HASH_MODE_4_CHILDREN, 4, vec![]);
        assert_eq!(custom.expected_public_inputs_hash, pi_hash);
        assert_eq!(custom.reward_tree_node_index, 21);
        assert_eq!(custom.reward_tree_node_level, 9);
        assert_eq!(custom.reward_tree_hash_mode, PROOF_REWARD_TREE_HASH_MODE_4_CHILDREN);
        assert_eq!(custom.reward_tree_node_children, 4);
        assert!(custom.dependencies.is_empty());
    }

    #[test]
    fn compute_reward_tagged_expected_public_inputs_hashes_inputs_with_reward() {
        let tag = hash(9);
        let value = metadata(PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD, 2);
        let children = [hash(1), hash(2)];
        let reward = value.get_new_rewards_tag_tree_value::<PoseidonHasher>(tag, &children).unwrap();

        assert_eq!(
            value.compute_reward_tagged_expected_public_inputs::<PoseidonHasher>(tag, &children).unwrap(),
            PoseidonHasher::two_to_one(&value.expected_public_inputs_hash, &reward)
        );
        // A wrong child count must propagate the mode error instead of hashing.
        assert!(value.compute_reward_tagged_expected_public_inputs::<PoseidonHasher>(tag, &[]).is_err());
    }

    #[test]
    fn lift_child_updates_store_a_single_node_and_validate_the_value() {
        let tag = hash(9);
        let value = metadata(PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD, 1);
        let children = [hash(1)];
        let reward = value.get_new_rewards_tag_tree_value::<PoseidonHasher>(tag, &children).unwrap();

        let updates = value.get_new_rewards_tag_tree_updates::<PoseidonHasher>(tag, &children, reward).unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].0, value.get_reward_tree_node_key());
        assert_eq!(updates[0].1.tag, tag);
        assert_eq!(updates[0].1.value, reward);

        assert!(value.get_new_rewards_tag_tree_updates::<PoseidonHasher>(tag, &[], reward).is_err());
        assert!(value.get_new_rewards_tag_tree_updates::<PoseidonHasher>(tag, &children, hash(99)).is_err());
    }

    #[test]
    fn no_hash_children_updates_store_a_single_node() {
        let tag = hash(9);
        let value = metadata(PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN, 0);
        let reward = value.get_new_rewards_tag_tree_value::<PoseidonHasher>(tag, &[]).unwrap();

        let updates = value.get_new_rewards_tag_tree_updates::<PoseidonHasher>(tag, &[], reward).unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].0, value.get_reward_tree_node_key());
        assert_eq!(updates[0].1.tag, tag);
        assert_eq!(updates[0].1.value, reward);

        assert!(value.get_new_rewards_tag_tree_updates::<PoseidonHasher>(tag, &[], hash(99)).is_err());
    }
}
impl<Hash: QPGenRandom, JobId: QPGenRandom> QPGenRandom for PsyProvingJobMetadata<Hash, JobId> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let expected_public_inputs_hash = Hash::qp_rand_gen();
        let reward_tree_node_index = rng.gen();
        let reward_tree_node_level = rng.gen();
        let reward_tree_hash_mode = rng.gen();
        let reward_tree_node_children = rng.gen();
        let dependencies_len: usize = rng.gen_range(0..10);
        let mut dependencies = Vec::with_capacity(dependencies_len);
        for _ in 0..dependencies_len {
            dependencies.push(JobId::qp_rand_gen());
        }
        Self {
            expected_public_inputs_hash,
            reward_tree_node_index,
            reward_tree_node_level,
            reward_tree_hash_mode,
            reward_tree_node_children,
            dependencies,
        }
    }
}

impl<Hash, JobId> PsyProvingJobMetadata<Hash, JobId> {
    pub fn new_leaf(expected_public_inputs_hash: Hash, reward_node_key: SimpleMerkleNodeKey, dependencies: Vec<JobId>) -> Self {
        Self {
            expected_public_inputs_hash,
            reward_tree_node_index: reward_node_key.index,
            reward_tree_node_level: reward_node_key.level,
            reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN,
            reward_tree_node_children: 0,
            dependencies,
        }
    }
    pub fn new_inner_standard(expected_public_inputs_hash: Hash, reward_node_key: SimpleMerkleNodeKey, dependencies: Vec<JobId>) -> Self {
        Self {
            expected_public_inputs_hash,
            reward_tree_node_index: reward_node_key.index,
            reward_tree_node_level: reward_node_key.level,
            reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD,
            reward_tree_node_children: dependencies.len() as u16,
            dependencies,
        }
    }
    pub fn new_3_to_1_double_reward(expected_public_inputs_hash: Hash, reward_node_key: SimpleMerkleNodeKey, dependencies: Vec<JobId>) -> Self {
        Self {
            expected_public_inputs_hash,
            reward_tree_node_index: reward_node_key.index,
            reward_tree_node_level: reward_node_key.level,
            reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_3_CHILDREN_DOUBLE_REWARD,
            reward_tree_node_children: 3,
            dependencies,
        }
    }
    pub fn new(
        expected_public_inputs_hash: Hash,
        reward_tree_node_index: u64,
        reward_tree_node_level: u8,
        reward_tree_hash_mode: u8,
        reward_tree_node_children: u16,
        dependencies: Vec<JobId>,
    ) -> Self {
        Self {
            expected_public_inputs_hash,
            reward_tree_node_index,
            reward_tree_node_level,
            reward_tree_hash_mode,
            reward_tree_node_children,
            dependencies,
        }
    }
}

impl<Hash: Q256BitHash, JobId: QJobIdBase> PsyCanonicalSerializeMetadata for PsyProvingJobMetadata<Hash, JobId> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<Hash: Q256BitHash, JobId: QJobIdBase> FallbackPsySerializeCanonical for PsyProvingJobMetadata<Hash, JobId> {
    fn fallback_pio_serialized_size(&self) -> usize {
        32 + 8 + (1 + 1 + 2) + 4 + self.dependencies.len() * QJOB_ID_SERIALIZED_SIZE
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.expected_public_inputs_hash.into_owned_32bytes())?;
        writer.psy_write_u64(self.reward_tree_node_index)?;
        writer.psy_write_u8(self.reward_tree_node_level)?;
        writer.psy_write_u8(self.reward_tree_hash_mode)?;
        writer.psy_write_u16(self.reward_tree_node_children)?;
        writer.psy_write_vec_length(self.dependencies.len())?;
        for dep in self.dependencies.iter() {
            writer.psy_write_bytes_fixed(&dep.to_bytes_fixed())?;
        }

        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let expected_public_inputs_hash = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let reward_tree_node_index = reader.psy_read_u64()?;
        let reward_tree_node_level = reader.psy_read_u8()?;
        let reward_tree_hash_mode = reader.psy_read_u8()?;
        let reward_tree_node_children = reader.psy_read_u16()?;
        let dependencies_len = reader.psy_read_vec_length()? as usize;
        let mut dependencies = Vec::with_capacity(dependencies_len);
        for _ in 0..dependencies_len {
            let dep = JobId::from_bytes_fixed(&reader.psy_read_bytes_fixed()?)?;
            dependencies.push(dep);
        }
        Ok(Self {
            expected_public_inputs_hash,
            reward_tree_node_index,
            reward_tree_node_level,
            reward_tree_hash_mode,
            reward_tree_node_children,
            dependencies,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PsyProvingJobMetadata,
    { Hash: Q256BitHash, JobId: QJobIdBase } => { Hash, JobId }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash, JobId: QJobIdBase> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for PsyProvingJobMetadata<Hash, JobId>
{
}

pser::impl_psy_ser_basic_tests_fallback!(
    PsyProvingJobMetadata,
    { parth_core::PHash, psy_core::job::job_id::QProvingJobDataID },
    psy_proving_job_metadata_tests
);


#[cfg(test)]
mod mode_four_tests {
    use parth_core::{crypto::hash::{tag_tree::hash_tag_tree_node_four, traits::MerkleHasher}, utils::QPGenRandom};

    use super::*;

    #[test]
    fn test_mode_4_children_tag_value_and_updates_are_consistent() -> anyhow::Result<()> {
        type Hash = parth_core::PHash;
        type Hasher = parth_core::pgoldilocks::PoseidonHasher;

        let tag = Hash::qp_rand_gen();
        let children = [
            Hash::qp_rand_gen(),
            Hash::qp_rand_gen(),
            Hash::qp_rand_gen(),
            Hash::qp_rand_gen(),
        ];
        let deps = (0..4).map(|_| QProvingJobDataID::qp_rand_gen()).collect::<Vec<_>>();

        let metadata = PsyProvingJobMetadata::<Hash, QProvingJobDataID> {
            expected_public_inputs_hash: Hash::qp_rand_gen(),
            reward_tree_node_index: 0,
            reward_tree_node_level: 1,
            reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_4_CHILDREN,
            reward_tree_node_children: 4,
            dependencies: deps,
        };

        let reward_tree_value = metadata.get_new_rewards_tag_tree_value::<Hasher>(tag, &children)?;
        let expected = hash_tag_tree_node_four::<Hash, Hasher>(&children[0], &children[1], &children[2], &children[3], &tag);
        assert_eq!(reward_tree_value, expected);

        let updates = metadata.get_new_rewards_tag_tree_updates::<Hasher>(tag, &children, reward_tree_value)?;
        assert_eq!(updates.len(), 3);
        assert_eq!(updates[0].0, metadata.get_reward_tree_node_key());
        assert_eq!(updates[0].1.value, reward_tree_value);
        assert_eq!(updates[1].0, metadata.get_reward_tree_node_key().right_child());
        assert_eq!(updates[2].0, metadata.get_reward_tree_node_key().right_child().right_child());

        // wrong child count must fail
        assert!(metadata.get_new_rewards_tag_tree_value::<Hasher>(tag, &children[..3]).is_err());
        Ok(())
    }
}
