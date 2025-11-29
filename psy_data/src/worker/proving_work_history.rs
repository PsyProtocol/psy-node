use parth_core::{QJOB_ID_SERIALIZED_SIZE, QJobIdBase, crypto::hash::{tag_tree::hash_tag_tree_node, traits::{MerkleHasher, ZeroableHash}}, data::hash::merkle_node_key::SimpleMerkleNodeKey, protocol::core_types::Q256BitHash, utils::QPGenRandom};
use psy_core::job::job_id::QProvingJobDataID;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::worker::{api_response::PROVING_JOB_NODE_TYPE_REALM, metadata::{PROOF_REWARD_TREE_HASH_MODE_3_CHILDREN_DOUBLE_REWARD, PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD, PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN}};


#[pderive::serialize_copy_hash_job_id_ts]
#[ts(export, concrete(Hash = parth_core::PHash, JobId = QProvingJobDataID))]
#[repr(C)]
pub struct PsyProvingJobClaimMetadata<Hash, JobId> {
    pub job_id: JobId,
    pub reward_tree_tag: Hash,
    pub reward_tree_tag_preimage: Hash,
    pub proving_duration_ms: u64,
    pub job_submitted_at: u64,
    pub unique_pending_id: u64,
    pub realm_id: u64,
    pub realm_sub_id: u64,
    pub reward_tree_node_key: SimpleMerkleNodeKey,
    pub reward_tree_hash_mode: u8,      // How to hash this node's children when computing the reward tree hash
    pub reward_tree_node_children: u16, // Number of children this node has in the reward tree, used to hint at how to hash
    pub node_type: u8,
    pub api_url_hash: [u8; 32],
}

impl<Hash: Default, JobId: Default> Default for PsyProvingJobClaimMetadata<Hash, JobId> {
    fn default() -> Self {
        Self {
            job_id: JobId::default(),
            reward_tree_tag: Hash::default(),
            reward_tree_tag_preimage: Hash::default(),
            proving_duration_ms: 0,
            job_submitted_at: 0,
            unique_pending_id: 0,
            realm_id: 0,
            realm_sub_id: 0,
            reward_tree_node_key : SimpleMerkleNodeKey { index: 0, level: 0 },
            reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN,
            reward_tree_node_children: 0,
            node_type: PROVING_JOB_NODE_TYPE_REALM,
            api_url_hash: [0u8; 32],
        }
    }
}
impl<Hash: ZeroableHash + Copy, JobId> PsyProvingJobClaimMetadata<Hash, JobId> {

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
                hash_tag_tree_node::<Hash, Hasher>(&children[0], &Hash::get_zero_value(), &tag)
            }
            _ => anyhow::bail!("Unknown reward tree hash mode: {}", self.reward_tree_hash_mode),
        };
        Ok(res)
    }
}
impl<Hash: QPGenRandom, JobId: QPGenRandom> QPGenRandom for PsyProvingJobClaimMetadata<Hash, JobId> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        Self {
            job_id: JobId::qp_rand_gen(),
            reward_tree_tag: Hash::qp_rand_gen(),
            reward_tree_tag_preimage: Hash::qp_rand_gen(),
            proving_duration_ms: rng.gen(),
            job_submitted_at: rng.gen(),
            unique_pending_id: rng.gen(),
            realm_id: rng.gen(),
            realm_sub_id: rng.gen(),
            reward_tree_node_key : SimpleMerkleNodeKey { index: rng.gen(), level: rng.gen() },
            reward_tree_hash_mode: (rng.gen::<u8>()&1) + 1,
            reward_tree_node_children: rng.gen(),
            node_type: rng.gen(),
            api_url_hash: rng.gen(),
        }
    }
}

impl<Hash, JobId> PsyProvingJobClaimMetadata<Hash, JobId> {
}

impl<Hash: Q256BitHash, JobId: QJobIdBase> PsyCanonicalSerializeMetadata for PsyProvingJobClaimMetadata<Hash, JobId> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<Hash: Q256BitHash, JobId: QJobIdBase> FallbackPsySerializeCanonical for PsyProvingJobClaimMetadata<Hash, JobId> {
    fn fallback_pio_serialized_size(&self) -> usize {
        QJOB_ID_SERIALIZED_SIZE + 32*2 + 8*5 + SimpleMerkleNodeKey::FIXED_SIZE + 1 + 2 + 1 + 32
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.job_id.to_bytes_fixed())?;
        writer.psy_write_bytes_fixed(&self.reward_tree_tag.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.reward_tree_tag_preimage.into_owned_32bytes())?;
        writer.psy_write_u64(self.proving_duration_ms)?;
        writer.psy_write_u64(self.job_submitted_at)?;
        writer.psy_write_u64(self.unique_pending_id)?;
        writer.psy_write_u64(self.realm_id)?;
        writer.psy_write_u64(self.realm_sub_id)?;
        self.reward_tree_node_key.pio_write_to_io(writer)?;
        writer.psy_write_u8(self.reward_tree_hash_mode)?;
        writer.psy_write_u16(self.reward_tree_node_children)?;
        writer.psy_write_u8(self.node_type)?;
        writer.psy_write_bytes_fixed(&self.api_url_hash)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let job_id = JobId::from_bytes_fixed(&reader.psy_read_bytes_fixed()?)?;
        let reward_tree_tag = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let reward_tree_tag_preimage = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let proving_duration_ms = reader.psy_read_u64()?;
        let job_submitted_at = reader.psy_read_u64()?;
        let unique_pending_id = reader.psy_read_u64()?;
        let realm_id = reader.psy_read_u64()?;
        let realm_sub_id = reader.psy_read_u64()?;
        let reward_tree_node_key = SimpleMerkleNodeKey::pio_read_from_io(reader)?;
        let reward_tree_hash_mode = reader.psy_read_u8()?;
        let reward_tree_node_children = reader.psy_read_u16()?;
        let node_type = reader.psy_read_u8()?;
        let api_url_hash = reader.psy_read_bytes_32()?;
        Ok(Self {
            job_id,
            reward_tree_tag,
            reward_tree_tag_preimage,
            proving_duration_ms,
            job_submitted_at,
            unique_pending_id,
            realm_id,
            realm_sub_id,
            reward_tree_node_key,
            reward_tree_hash_mode,
            reward_tree_node_children,
            node_type,
            api_url_hash: api_url_hash,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PsyProvingJobClaimMetadata,
    { Hash: Q256BitHash, JobId: QJobIdBase } => { Hash, JobId }
);

#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash, JobId: QJobIdBase> psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for PsyProvingJobMetadata<Hash, JobId>
{
}

pser::impl_psy_ser_basic_tests_fallback!(
    PsyProvingJobClaimMetadata,
    { parth_core::PHash, psy_core::job::job_id::QProvingJobDataID },
    psy_proving_job_claim_metadata_basic_tests
);

