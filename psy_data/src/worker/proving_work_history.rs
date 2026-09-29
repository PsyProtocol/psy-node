use parth_core::{QJOB_ID_SERIALIZED_SIZE, QJobIdBase, crypto::hash::{tag_tree::{hash_tag_tree_node, hash_tag_tree_node_four}, traits::{MerkleHasher, ZeroableHash}}, data::hash::merkle_node_key::SimpleMerkleNodeKey, protocol::core_types::Q256BitHash, utils::QPGenRandom};
use psy_core::job::job_id::QProvingJobDataID;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::worker::{api_response::PROVING_JOB_NODE_TYPE_REALM, metadata::{PROOF_REWARD_TREE_HASH_MODE_3_CHILDREN_DOUBLE_REWARD, PROOF_REWARD_TREE_HASH_MODE_4_CHILDREN, PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD, PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN}};


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
            PROOF_REWARD_TREE_HASH_MODE_4_CHILDREN => {
                if children.len() != 4 {
                    anyhow::bail!("Expected 4 children for 4-children reward hash mode, got {}", children.len());
                }
                // NOTE: uses the same nested layout as
                // PsyProvingJobMetadata::get_new_rewards_tag_tree_value
                hash_tag_tree_node_four::<Hash, Hasher>(&children[0], &children[1], &children[2], &children[3], &tag)
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
    for PsyProvingJobClaimMetadata<Hash, JobId>
{
}

pser::impl_psy_ser_basic_tests_fallback!(
    PsyProvingJobClaimMetadata,
    { parth_core::PHash, psy_core::job::job_id::QProvingJobDataID },
    psy_proving_job_claim_metadata_basic_tests
);

#[cfg(test)]
mod behavior_tests {
    use super::*;
    use parth_core::{pgoldilocks::PoseidonHasher, PHash};

    fn hash(value: u64) -> PHash {
        PHash::from_values(value, 0, 0, 0)
    }

    fn metadata(mode: u8) -> PsyProvingJobClaimMetadata<PHash, u8> {
        PsyProvingJobClaimMetadata {
            reward_tree_hash_mode: mode,
            ..Default::default()
        }
    }

    #[test]
    fn claim_reward_modes_validate_children_and_hash_consistently() {
        let tag = hash(9);
        let cases = [
            (PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN, vec![]),
            (PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD, vec![hash(1), hash(2)]),
            (PROOF_REWARD_TREE_HASH_MODE_3_CHILDREN_DOUBLE_REWARD, vec![hash(1), hash(2), hash(3)]),
            (PROOF_REWARD_TREE_HASH_MODE_4_CHILDREN, vec![hash(1), hash(2), hash(3), hash(4)]),
            (PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD, vec![hash(1)]),
        ];
        for (mode, children) in cases {
            assert_ne!(
                metadata(mode)
                    .get_new_rewards_tag_tree_value::<PoseidonHasher>(tag, &children)
                    .unwrap(),
                PHash::default()
            );
        }

        assert!(metadata(PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD)
            .get_new_rewards_tag_tree_value::<PoseidonHasher>(tag, &[hash(1)])
            .is_err());
        assert!(metadata(PROOF_REWARD_TREE_HASH_MODE_3_CHILDREN_DOUBLE_REWARD)
            .get_new_rewards_tag_tree_value::<PoseidonHasher>(tag, &[hash(1), hash(2)])
            .is_err());
        assert!(metadata(PROOF_REWARD_TREE_HASH_MODE_4_CHILDREN)
            .get_new_rewards_tag_tree_value::<PoseidonHasher>(tag, &[hash(1), hash(2), hash(3)])
            .is_err());
        assert!(metadata(PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD)
            .get_new_rewards_tag_tree_value::<PoseidonHasher>(tag, &[])
            .is_err());
        assert!(metadata(255)
            .get_new_rewards_tag_tree_value::<PoseidonHasher>(tag, &[])
            .is_err());
    }

    #[test]
    fn claim_default_matches_realm_no_hash_leaf() {
        let value = PsyProvingJobClaimMetadata::<PHash, u8>::default();
        assert_eq!(value.job_id, u8::default());
        assert_eq!(value.reward_tree_tag, PHash::default());
        assert_eq!(value.reward_tree_tag_preimage, PHash::default());
        assert_eq!(value.proving_duration_ms, 0);
        assert_eq!(value.job_submitted_at, 0);
        assert_eq!(value.unique_pending_id, 0);
        assert_eq!(value.realm_id, 0);
        assert_eq!(value.realm_sub_id, 0);
        assert_eq!(value.reward_tree_node_key, SimpleMerkleNodeKey { index: 0, level: 0 });
        assert_eq!(value.reward_tree_hash_mode, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN);
        assert_eq!(value.reward_tree_node_children, 0);
        assert_eq!(value.node_type, PROVING_JOB_NODE_TYPE_REALM);
        assert_eq!(value.api_url_hash, [0u8; 32]);
    }

    #[test]
    fn claim_tag_formulas_match_tag_tree_helpers() {
        let tag = hash(9);
        let zero = PHash::get_zero_value();

        // No-hash mode folds the tag together with two zero children.
        let no_hash = metadata(PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN)
            .get_new_rewards_tag_tree_value::<PoseidonHasher>(tag, &[])
            .unwrap();
        assert_eq!(no_hash, hash_tag_tree_node::<PHash, PoseidonHasher>(&zero, &zero, &tag));

        // Standard mode hashes the two children together with the tag.
        let children = [hash(1), hash(2)];
        let standard = metadata(PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD)
            .get_new_rewards_tag_tree_value::<PoseidonHasher>(tag, &children)
            .unwrap();
        assert_eq!(standard, hash_tag_tree_node::<PHash, PoseidonHasher>(&children[0], &children[1], &tag));

        // 3-children double-reward nests [c0, [c1, c2]] with a zero right sibling.
        let children3 = [hash(1), hash(2), hash(3)];
        let double = metadata(PROOF_REWARD_TREE_HASH_MODE_3_CHILDREN_DOUBLE_REWARD)
            .get_new_rewards_tag_tree_value::<PoseidonHasher>(tag, &children3)
            .unwrap();
        let left = hash_tag_tree_node::<PHash, PoseidonHasher>(&children3[0], &children3[1], &tag);
        let right = hash_tag_tree_node::<PHash, PoseidonHasher>(&children3[2], &zero, &tag);
        assert_eq!(double, hash_tag_tree_node::<PHash, PoseidonHasher>(&left, &right, &tag));

        // Lift-child mode pads the single child with a zero sibling.
        let lift = metadata(PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD)
            .get_new_rewards_tag_tree_value::<PoseidonHasher>(tag, &[hash(1)])
            .unwrap();
        assert_eq!(lift, hash_tag_tree_node::<PHash, PoseidonHasher>(&hash(1), &zero, &tag));

        // 4-children mode uses the dedicated four-way tag tree helper.
        let children4 = [hash(1), hash(2), hash(3), hash(4)];
        let four = metadata(PROOF_REWARD_TREE_HASH_MODE_4_CHILDREN)
            .get_new_rewards_tag_tree_value::<PoseidonHasher>(tag, &children4)
            .unwrap();
        assert_eq!(
            four,
            hash_tag_tree_node_four::<PHash, PoseidonHasher>(&children4[0], &children4[1], &children4[2], &children4[3], &tag)
        );
    }
}
