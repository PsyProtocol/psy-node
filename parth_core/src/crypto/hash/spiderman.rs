use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};
use serde::{de::DeserializeOwned, Serialize};

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
use crate::protocol::core_types::Q256BitHash;
use crate::{crypto::hash::{merkle_proof::{DeltaMerkleProofCore, MerkleProofCore}, traits::{MerkleHasher, MerkleZeroHasher, ZeroableHash}}, data::serializable::QPDSerializable, utils::{QPGenRandom, math::log2_strict}};
use crate::crypto::hash::traits::MerkleLeafHasher;
use pser::{QBytesSerialize, QBytesDeserialize};

fn _hash_merkle_leaves_partial<Hash: PartialEq + Copy, Hasher: MerkleZeroHasher<Hash>>(
    leaves: &[Hash],
) -> anyhow::Result<Hash> {
    if leaves.len() == 0 {
        anyhow::bail!("Cannot compute Merkle root of zero leaves");
    }else if leaves.len() == 1 {
        return Ok(leaves[0]);
    }else if leaves.len() == 2 {
        return Ok(Hasher::two_to_one(&leaves[0], &leaves[1]));
    }



    let mut current_nodes_level_from_bottom = 0;
    let nodes_len = leaves.len();
    let has_odd_nodes = nodes_len & 1;
    let even_pairs_count = nodes_len / 2;
    let next_count = even_pairs_count + has_odd_nodes;
    let mut current_level = Vec::with_capacity(next_count);
    for i in 0..even_pairs_count {
        current_level.push(Hasher::two_to_one(&leaves[2*i], &leaves[2*i+1]));
    }
    if has_odd_nodes == 1 {
        current_level.push(Hasher::two_to_one(&leaves[nodes_len - 1], &Hasher::get_zero_hash(current_nodes_level_from_bottom)));
    }

    current_nodes_level_from_bottom += 1;
    while current_level.len() > 1 {
        for i in 0..(current_level.len() / 2) {
            current_level[i] = Hasher::two_to_one(&current_level[2*i], &current_level[2*i+1]);
        }
        let has_odd_nodes = current_level.len() & 1;
        let even_pairs_count = current_level.len() / 2;
        let next_count = even_pairs_count + has_odd_nodes;
        if has_odd_nodes == 1 {
            current_level[even_pairs_count] = Hasher::two_to_one(&current_level[current_level.len() - 1], &Hasher::get_zero_hash(current_nodes_level_from_bottom));
        }
        current_level.truncate(next_count);
        current_nodes_level_from_bottom += 1;
    }

    Ok(current_level[0])
}

#[pderive::serialize_clone_ts_export]
pub struct SpidermanUpdateProof<Hash> {
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

        web_proof_old_leaves.extend_from_slice(existing_leaves);
        for _ in 0..zero_hashes_to_add {
            web_proof_old_leaves.push(Hash::get_zero_value());
        }

        let mut web_proof_new_leaves = Vec::with_capacity(leaves_len);
        let zero_hashes_to_add = leaves_len - (existing_leaves.len() + new_leaves.len());

        web_proof_new_leaves.extend_from_slice(existing_leaves);
        web_proof_new_leaves.extend_from_slice(new_leaves);
        for _ in 0..zero_hashes_to_add {
            web_proof_new_leaves.push(Hash::get_zero_value());
        }

        // hash the old sub tree
        let computed_old_web_root = H::compute_root_from_leaves(&web_proof_old_leaves).unwrap();

        // hash the new sub tree
        let computed_new_web_root = H::compute_root_from_leaves(&web_proof_new_leaves).unwrap();


        // move the index from the leaf level to the root of the web sub-tree
        let top_line_index = old_proof_to_inside.index >> (web_tree_height as u64);

        // Since we moved up to the level of the web sub-tree's root:
        // The siblings for the top-line proof are ONLY the ones
        // ABOVE the web subtree. The first `web_tree_height` siblings
        // from the original proof belong to the web and must be excluded.
        let siblings = old_proof_to_inside.siblings[web_tree_height..].to_vec();
        
        let top_line_proof = DeltaMerkleProofCore::from_params::<H>(
            top_line_index,
            computed_old_web_root,
            computed_new_web_root,
            siblings,
        );

        Self {
            top_line_proof,
            web_proof_old_leaves,
            web_proof_new_leaves,
        }
    }
}
impl<Hash: PartialEq + Copy> SpidermanUpdateProof<Hash> {

    pub fn from_delta_merkle_proofs<H: MerkleHasher<Hash>>(
        delta_merkle_proofs: &[DeltaMerkleProofCore<Hash>],
    ) -> Self {
        let leaves_len = delta_merkle_proofs.len();
        let web_tree_height = log2_strict(leaves_len);
        //let full_tree_height = delta_merkle_proofs[0].siblings.len();
        //let top_line_height = full_tree_height-web_tree_height;

        let old_leaves = delta_merkle_proofs
            .iter()
            .map(|x| x.old_value)
            .collect::<Vec<_>>();
        let new_leaves = delta_merkle_proofs
            .iter()
            .map(|x| x.new_value)
            .collect::<Vec<_>>();

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
    /// Verifies the entire Spiderman proof.
    ///
    /// This checks that:
    /// 1. The old and new leaf sets correctly hash to the old and new values in the top-line proof.
    /// 2. The top-line proof itself is a valid Delta Merkle proof.
    pub fn verify<H: MerkleHasher<Hash>>(&self) -> bool {
        // Ensure leaf vectors have the same, power-of-two length.
        let leaves_len = self.web_proof_new_leaves.len();
        if self.web_proof_old_leaves.len() != leaves_len || !leaves_len.is_power_of_two() {
            return false;
        }

        // Verify the top-line proof first.
        if !self.top_line_proof.verify::<H>() {
            return false;
        }

        // Verify that the old leaves compute to the old sub-tree root.
        let computed_old_web_root = H::compute_root_from_leaves(&self.web_proof_old_leaves).unwrap();
        if computed_old_web_root != self.top_line_proof.old_value {
            return false;
        }

        // Verify that the new leaves compute to the new sub-tree root.
        let computed_new_web_root = H::compute_root_from_leaves(&self.web_proof_new_leaves).unwrap();
        if computed_new_web_root != self.top_line_proof.new_value {
            return false;
        }

        true
    }
}



impl<Hash: Copy + PartialEq +  Serialize + DeserializeOwned> QPDSerializable for SpidermanUpdateProof<Hash> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        //b1incode::serialize(self).map_err(|e| anyhow::anyhow!(e))
        self.to_qbytes()
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        //b1incode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
        Self::from_qbytes(bytes)
    }
}










#[cfg(feature = "rand")]
impl<Hash: QPGenRandom> QPGenRandom for SpidermanUpdateProof<Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            top_line_proof: DeltaMerkleProofCore::qp_rand_gen(),
            web_proof_old_leaves: Hash::qp_rand_gen_vec(rand::random::<u8>() as usize + 1),
            web_proof_new_leaves: Hash::qp_rand_gen_vec(rand::random::<u8>() as usize + 1),
        }
    }
}





impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for SpidermanUpdateProof<Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}
impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for SpidermanUpdateProof<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
       self.top_line_proof.pio_serialized_size() + 4 + (self.web_proof_old_leaves.len() * 32) + 4 + (self.web_proof_new_leaves.len() * 32)
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.top_line_proof.pio_write_to_io(writer)?;
        writer.psy_write_vec_length(self.web_proof_old_leaves.len())?;
        for leaf in &self.web_proof_old_leaves {
            writer.psy_write_bytes_fixed(&leaf.into_owned_32bytes())?;
        }
        writer.psy_write_vec_length(self.web_proof_new_leaves.len())?;
        for leaf in &self.web_proof_new_leaves {
            writer.psy_write_bytes_fixed(&leaf.into_owned_32bytes())?;
        }
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let top_line_proof = DeltaMerkleProofCore::<Hash>::pio_read_from_io(reader)?;
        let old_leaves_len = reader.psy_read_vec_length()?;
        let mut web_proof_old_leaves = Vec::with_capacity(old_leaves_len);
        for _ in 0..old_leaves_len {
            let hash_bytes = reader.psy_read_bytes_32()?;
            let hash = Hash::from_owned_32bytes(hash_bytes);
            web_proof_old_leaves.push(hash);
        }
        let new_leaves_len = reader.psy_read_vec_length()?;
        let mut web_proof_new_leaves = Vec::with_capacity(new_leaves_len);
        for _ in 0..new_leaves_len {
            let hash_bytes = reader.psy_read_bytes_32()?;
            let hash = Hash::from_owned_32bytes(hash_bytes);
            web_proof_new_leaves.push(hash);
        }
        Ok(Self {
            top_line_proof,
            web_proof_old_leaves,
            web_proof_new_leaves,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    SpidermanUpdateProof,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for SpidermanUpdateProof<Hash> {}


pser::impl_psy_ser_basic_tests!(
    SpidermanUpdateProof,
    // Note the use of concrete types here
    {  crate::PHash },
    spiderman_update_proof_basic_ser_tests,
    true
);
