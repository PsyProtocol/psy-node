use std::collections::HashSet;

use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::{crypto::hash::{merkle_proof::DeltaMerkleProofCore, traits::MerkleHasher}, data::hash::merkle_node_key::SimpleMerkleNodeKey, protocol::core_types::Q256BitHash, utils::QPGenRandom};


#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = crate::PHash))]
pub struct UpdateNearestCommonAncestorProof<Hash> {
    pub old_nearest_common_ancestor_value: Hash,
    pub new_nearest_common_ancestor_value: Hash,

    pub child_a: DeltaMerkleProofCore<Hash>,
    pub child_b: DeltaMerkleProofCore<Hash>,

    pub nearest_common_ancestor_level: u8,
    pub nearest_common_ancestor_index: u64,

    pub level_a: u8,
    pub level_b: u8,
}
#[cfg(feature = "rand")]
impl<Hash: QPGenRandom> QPGenRandom for UpdateNearestCommonAncestorProof<Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            old_nearest_common_ancestor_value: Hash::qp_rand_gen(),
            new_nearest_common_ancestor_value: Hash::qp_rand_gen(),
            child_a: DeltaMerkleProofCore::qp_rand_gen(),
            child_b: DeltaMerkleProofCore::qp_rand_gen(),
            nearest_common_ancestor_level: rand::random::<u8>(),
            nearest_common_ancestor_index: rand::random::<u64>(),
            level_a: rand::random::<u8>(),
            level_b: rand::random::<u8>(),
        }
    }
}

impl< Hash: Q256BitHash> PsyCanonicalSerializeMetadata for UpdateNearestCommonAncestorProof<Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}
impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for UpdateNearestCommonAncestorProof<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        32*2 + self.child_a.pio_serialized_size() + self.child_b.pio_serialized_size() + 1 + 8 + 1 + 1
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes(&self.old_nearest_common_ancestor_value.into_owned_32bytes())?;
        writer.psy_write_bytes(&self.new_nearest_common_ancestor_value.into_owned_32bytes())?;
        self.child_a.pio_write_to_io(writer)?;
        self.child_b.pio_write_to_io(writer)?;
        writer.psy_write_u8(self.nearest_common_ancestor_level)?;
        writer.psy_write_u64(self.nearest_common_ancestor_index)?;
        writer.psy_write_u8(self.level_a)?;
        writer.psy_write_u8(self.level_b)
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let old_nearest_common_ancestor_value = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let new_nearest_common_ancestor_value = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let child_a = DeltaMerkleProofCore::pio_read_from_io(reader)?;
        let child_b = DeltaMerkleProofCore::pio_read_from_io(reader)?;
        let nearest_common_ancestor_level = reader.psy_read_u8()?;
        let nearest_common_ancestor_index = reader.psy_read_u64()?;
        let level_a = reader.psy_read_u8()?;
        let level_b = reader.psy_read_u8()?;
        Ok(Self {
            old_nearest_common_ancestor_value,
            new_nearest_common_ancestor_value,
            child_a,
            child_b,
            nearest_common_ancestor_level,
            nearest_common_ancestor_index,
            level_a,
            level_b,
        })
    }
}
#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    UpdateNearestCommonAncestorProof,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for UpdateNearestCommonAncestorProof<Hash> {}


pser::impl_psy_ser_basic_tests_fallback!(
    UpdateNearestCommonAncestorProof,
    { crate::PHash },
    update_nearest_common_ancestor_proof_tests,
    true
);



impl<Hash: PartialEq + Copy> UpdateNearestCommonAncestorProof<Hash> {
    pub fn to_partial(&self) -> PartialUpdateNearestCommonAncestorProof<Hash> {
        PartialUpdateNearestCommonAncestorProof {
            child_a: self.child_a.clone(),
            child_b: self.child_b.clone(),
            nearest_common_ancestor_level: self.nearest_common_ancestor_level,
        }
    }
}

impl<Hash: PartialEq + Copy> From<UpdateNearestCommonAncestorProof<Hash>>
    for PartialUpdateNearestCommonAncestorProof<Hash>
{
    fn from(value: UpdateNearestCommonAncestorProof<Hash>) -> Self {
        PartialUpdateNearestCommonAncestorProof {
            child_a: value.child_a,
            child_b: value.child_b,
            nearest_common_ancestor_level: value.nearest_common_ancestor_level,
        }
    }
}

impl<Hash: PartialEq + Copy> From<&UpdateNearestCommonAncestorProof<Hash>>
    for PartialUpdateNearestCommonAncestorProof<Hash>
{
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
    pub fn verify<H: MerkleHasher<Hash>>(&self) -> bool {
        let solo_mask = !self.is_solo_filler() as u8;
        if self.level_a
            == (self.nearest_common_ancestor_level + (self.child_a.siblings.len() as u8) + solo_mask)
            && self.level_b
                == (self.nearest_common_ancestor_level
                    + (self.child_b.siblings.len() as u8)
                    + solo_mask)
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
                let is_a_right = self
                    .get_a_node_key()
                    .is_on_the_right_of(&self.get_b_node_key());

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

                return self.old_nearest_common_ancestor_value == computed_old_root
                    && self.new_nearest_common_ancestor_value == computed_new_root;
            }
        }

        false
    }
    pub fn validate<H: MerkleHasher<Hash>>(&self) {
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

        assert_eq!(
            nca_index_a, nca_index_b,
            "the children must agree on the nearest common ancestor index"
        );
        assert_eq!(
            nca_index_a, self.nearest_common_ancestor_index,
            "the children must with the nearest common ancestor index"
        );

        assert!(self.child_a.verify::<H>(), "child a is invalid");
        assert!(self.child_b.verify::<H>(), "child b is invalid");
        let is_a_right = self
            .get_a_node_key()
            .is_on_the_right_of(&self.get_b_node_key());

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

#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = crate::PHash))]
pub struct NCAProofsWithTopLine<Hash> {
    pub nca_proofs: Vec<UpdateNCAWithAdditionalLink<Hash>>,
    pub top_line_proof: DeltaMerkleProofCore<Hash>,
}

#[cfg(feature = "rand")]
impl<Hash: QPGenRandom> QPGenRandom for NCAProofsWithTopLine<Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            nca_proofs: QPGenRandom::qp_rand_gen_vec(rand::random::<u8>() as usize % 10 + 1),
            top_line_proof: DeltaMerkleProofCore::qp_rand_gen(),
        }
    }
}

impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for NCAProofsWithTopLine<Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for NCAProofsWithTopLine<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        4 + self.nca_proofs.iter().map(|p| p.pio_serialized_size()).sum::<usize>()
        + self.top_line_proof.pio_serialized_size()
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_vec_length(self.nca_proofs.len())?;
        for proof in &self.nca_proofs {
            proof.pio_write_to_io(writer)?;
        }
        self.top_line_proof.pio_write_to_io(writer)?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let nca_proofs_len = reader.psy_read_vec_length()?;
        let mut nca_proofs = Vec::with_capacity(nca_proofs_len);
        for _ in 0..nca_proofs_len {
            nca_proofs.push(UpdateNCAWithAdditionalLink::pio_read_from_io(reader)?);
        }
        let top_line_proof = DeltaMerkleProofCore::pio_read_from_io(reader)?;
        Ok(Self {
            nca_proofs,
            top_line_proof,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    NCAProofsWithTopLine,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for NCAProofsWithTopLine<Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    NCAProofsWithTopLine,
    { crate::PHash },
    nca_proofs_with_top_line_ser_tests,
    true
);

#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = crate::PHash))]
pub struct PartialNCAProofsWithTopLine<Hash> {
    pub nca_proofs: Vec<PartialUpdateNearestCommonAncestorProof<Hash>>,
    pub top_line_proof: DeltaMerkleProofCore<Hash>,
}

#[cfg(feature = "rand")]
impl<Hash: QPGenRandom> QPGenRandom for PartialNCAProofsWithTopLine<Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            nca_proofs: QPGenRandom::qp_rand_gen_vec(rand::random::<u8>() as usize % 10 + 1),
            top_line_proof: DeltaMerkleProofCore::qp_rand_gen(),
        }
    }
}

impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PartialNCAProofsWithTopLine<Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for PartialNCAProofsWithTopLine<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        4 + self.nca_proofs.iter().map(|p| p.pio_serialized_size()).sum::<usize>()
        + self.top_line_proof.pio_serialized_size()
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_vec_length(self.nca_proofs.len())?;
        for proof in &self.nca_proofs {
            proof.pio_write_to_io(writer)?;
        }
        self.top_line_proof.pio_write_to_io(writer)?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let nca_proofs_len = reader.psy_read_vec_length()?;
        let mut nca_proofs = Vec::with_capacity(nca_proofs_len);
        for _ in 0..nca_proofs_len {
            nca_proofs.push(PartialUpdateNearestCommonAncestorProof::pio_read_from_io(reader)?);
        }
        let top_line_proof = DeltaMerkleProofCore::pio_read_from_io(reader)?;
        Ok(Self {
            nca_proofs,
            top_line_proof,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PartialNCAProofsWithTopLine,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for PartialNCAProofsWithTopLine<Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    PartialNCAProofsWithTopLine,
    { crate::PHash },
    partial_nca_proofs_with_top_line_ser_tests,
    true
);


#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = crate::PHash))]
pub struct PartialUpdateNearestCommonAncestorProof<Hash> {
    pub child_a: DeltaMerkleProofCore<Hash>,
    pub child_b: DeltaMerkleProofCore<Hash>,

    pub nearest_common_ancestor_level: u8,
}


impl<Hash: QPGenRandom> QPGenRandom for PartialUpdateNearestCommonAncestorProof<Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            child_a: DeltaMerkleProofCore::qp_rand_gen(),
            child_b: DeltaMerkleProofCore::qp_rand_gen(),
            nearest_common_ancestor_level: rand::random::<u8>(),
        }
    }
}

impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PartialUpdateNearestCommonAncestorProof<Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for PartialUpdateNearestCommonAncestorProof<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        self.child_a.pio_serialized_size()
        + self.child_b.pio_serialized_size()
        + 1
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.child_a.pio_write_to_io(writer)?;
        self.child_b.pio_write_to_io(writer)?;
        writer.psy_write_u8(self.nearest_common_ancestor_level)?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let child_a = DeltaMerkleProofCore::pio_read_from_io(reader)?;
        let child_b = DeltaMerkleProofCore::pio_read_from_io(reader)?;
        let nearest_common_ancestor_level = reader.psy_read_u8()?;
        Ok(Self {
            child_a,
            child_b,
            nearest_common_ancestor_level,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PartialUpdateNearestCommonAncestorProof,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for PartialUpdateNearestCommonAncestorProof<Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    PartialUpdateNearestCommonAncestorProof,
    { crate::PHash },
    partial_update_nearest_common_ancestor_proof_ser_tests,
    true
);


impl<Hash> PartialUpdateNearestCommonAncestorProof<Hash> {
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
    pub fn compute_old_nca_value<H: MerkleHasher<Hash>>(&self) -> Hash {
        let is_a_right = self
            .get_a_node_key()
            .is_on_the_right_of(&self.get_b_node_key());

        if is_a_right {
            H::two_to_one(&self.child_b.old_root, &self.child_a.old_root)
        } else {
            H::two_to_one(&self.child_a.old_root, &self.child_b.old_root)
        }
    }
    pub fn compute_new_nca_value<H: MerkleHasher<Hash>>(&self) -> Hash {
        let is_a_right = self
            .get_a_node_key()
            .is_on_the_right_of(&self.get_b_node_key());

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
    pub fn into_full_proof<H: MerkleHasher<Hash>>(self) -> UpdateNearestCommonAncestorProof<Hash> {
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
}


impl<Hash: Copy> PartialUpdateNearestCommonAncestorProof<Hash> {
    pub fn to_full_proof<H: MerkleHasher<Hash>>(&self) -> UpdateNearestCommonAncestorProof<Hash> {
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
    pub fn from_delta_merkle_proof_pair<H: MerkleHasher<Hash>>(
        dmp_a: &DeltaMerkleProofCore<Hash>,
        dmp_b: &DeltaMerkleProofCore<Hash>,
    ) -> Self {
        let height = dmp_a.siblings.len() as u8;
        assert_eq!(
            dmp_a.siblings.len(),
            dmp_b.siblings.len(),
            "from_delta_merkle_proof_pair requires valid delta merkle proofs to the same root"
        );
        assert!(
            dmp_a.index != dmp_b.index,
            "delta merkle proofs must be different"
        );

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

#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = crate::PHash))]
pub struct PartialUpdateNCAWithAdditionalLink<Hash> {
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<Hash>,
    pub link_siblings: Vec<Hash>,
}
impl<Hash: PartialEq + Copy> PartialUpdateNCAWithAdditionalLink<Hash> {
    pub fn from_delta_merkle_proof_pair<H: MerkleHasher<Hash>>(
        dmp_a: &DeltaMerkleProofCore<Hash>,
        dmp_b: &DeltaMerkleProofCore<Hash>,
    ) -> Self {
        let height = dmp_a.siblings.len() as u8;
        assert_eq!(
            dmp_a.siblings.len(),
            dmp_b.siblings.len(),
            "from_delta_merkle_proof_pair requires valid delta merkle proofs to the same root"
        );
        assert!(
            dmp_a.index != dmp_b.index,
            "delta merkle proofs must be different"
        );

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
    pub fn from_delta_merkle_proof_pair_alt_height<H: MerkleHasher<Hash>>(
        dmp_a: &DeltaMerkleProofCore<Hash>,
        dmp_b: &DeltaMerkleProofCore<Hash>,
    ) -> Self {
        let height_a = dmp_a.siblings.len() as u8;
        let height_b = dmp_a.siblings.len() as u8;

        let leaf_key_a = SimpleMerkleNodeKey::new(height_a, dmp_a.index);
        let leaf_key_b = SimpleMerkleNodeKey::new(height_b, dmp_b.index);
        assert!(
            leaf_key_a != leaf_key_b,
            "delta merkle proofs must be different"
        );
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
    pub fn to_full_proof<H: MerkleHasher<Hash>>(&self) -> UpdateNCAWithAdditionalLink<Hash> {
        let nca_proof = self.nca_proof.to_full_proof::<H>();
        let link_proof = DeltaMerkleProofCore::from_params::<H>(
            nca_proof.nearest_common_ancestor_index,
            nca_proof.old_nearest_common_ancestor_value,
            nca_proof.new_nearest_common_ancestor_value,
            self.link_siblings.clone(),
        );
        UpdateNCAWithAdditionalLink {
            nca_proof,
            link_proof,
        }
    }
    pub fn into_full_proof<H: MerkleHasher<Hash>>(self) -> UpdateNCAWithAdditionalLink<Hash> {
        let nca_proof = self.nca_proof.into_full_proof::<H>();
        let link_proof = DeltaMerkleProofCore::from_params::<H>(
            nca_proof.nearest_common_ancestor_index,
            nca_proof.old_nearest_common_ancestor_value,
            nca_proof.new_nearest_common_ancestor_value,
            self.link_siblings,
        );
        UpdateNCAWithAdditionalLink {
            nca_proof,
            link_proof,
        }
    }
}

#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = crate::PHash))]
pub struct UpdateNCAWithAdditionalLink<Hash> {
    pub nca_proof: UpdateNearestCommonAncestorProof<Hash>,
    pub link_proof: DeltaMerkleProofCore<Hash>,
}


#[cfg(feature = "rand")]
impl<Hash: QPGenRandom> QPGenRandom for UpdateNCAWithAdditionalLink<Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            nca_proof: UpdateNearestCommonAncestorProof::<Hash>::qp_rand_gen(),
            link_proof: DeltaMerkleProofCore::<Hash>::qp_rand_gen(),
        }
    }
}

impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for UpdateNCAWithAdditionalLink<Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for UpdateNCAWithAdditionalLink<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
         self.nca_proof.pio_serialized_size() +
         self.link_proof.pio_serialized_size() 
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.nca_proof.pio_write_to_io(writer)?;
        self.link_proof.pio_write_to_io(writer)?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let nca_proof = UpdateNearestCommonAncestorProof::pio_read_from_io(reader)?;
        let link_proof = DeltaMerkleProofCore::pio_read_from_io(reader)?;
        Ok(Self {
            nca_proof,                                                            
            link_proof,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    UpdateNCAWithAdditionalLink,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for UpdateNCAWithAdditionalLink<Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    UpdateNCAWithAdditionalLink,
    { crate::PHash },
    update_nca_with_additional_link_ser_tests,
    true
);

impl<Hash: PartialEq + Copy> UpdateNCAWithAdditionalLink<Hash> {
    pub fn from_delta_merkle_proof_pair<H: MerkleHasher<Hash>>(
        dmp_a: &DeltaMerkleProofCore<Hash>,
        dmp_b: &DeltaMerkleProofCore<Hash>,
    ) -> Self {
        PartialUpdateNCAWithAdditionalLink::from_delta_merkle_proof_pair::<H>(dmp_a, dmp_b)
            .to_full_proof::<H>()
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
    pub fn verify<H: MerkleHasher<Hash>>(&self) -> bool {
        self.nca_proof.verify::<H>()
            && self.link_proof.verify::<H>()
            && self.nca_proof.old_nearest_common_ancestor_value == self.link_proof.old_value
            && self.nca_proof.new_nearest_common_ancestor_value == self.link_proof.new_value
    }
}

#[pderive::serialize_clone_hash_ts]
#[derive(Default)]
#[ts(export, concrete(Hash = crate::PHash))]
pub struct UpdateNCAProofsWithDependencies<Hash> {
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

