use parth_core::{
    QJOB_ID_SERIALIZED_SIZE, QJobIdBase, crypto::hash::{tag_tree::hash_tag_tree_node, traits::{MerkleHasher, ZeroableHash}}, data::hash::merkle_node_key::SimpleMerkleNodeKey, protocol::core_types::Q256BitHash, utils::QPGenRandom
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata};

pub const PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD: u8 = 0;
pub const PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN: u8 = 1;
pub const PROOF_REWARD_TREE_HASH_MODE_3_CHILDREN_DOUBLE_REWARD: u8 = 2;
pub const PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD: u8 = 3;

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
                let zero = Hash::get_zero_value();
                if children.len() != 3 {
                    anyhow::bail!("Expected 3 children for 3-children double reward hash mode, got {}", children.len());
                }
                let left_value = hash_tag_tree_node::<Hash, Hasher>(&children[0], &children[1], &tag);
                let right_value = hash_tag_tree_node::<Hash, Hasher>(&children[2], &zero, &tag);
                let top_value = hash_tag_tree_node::<Hash, Hasher>(&left_value, &right_value, &tag);
                top_value
            }
            PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD => {
                if children.len() == 0 {
                    anyhow::bail!("Expected at least 1 child for lift child hash mode, got 0");
                }
                children[0]
            }
            _ => anyhow::bail!("Unknown reward tree hash mode: {}", self.reward_tree_hash_mode),
        };
        Ok(res)
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

