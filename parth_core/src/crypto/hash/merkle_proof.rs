use pser::{QBytesDeserialize, QBytesSerialize};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::hash::traits::{CodeSerializableHash, MerkleHasher, MerkleZeroHasher, ZeroableHash},
    data::serializable::QPDSerializable,
    protocol::core_types::Q256BitHash,
    utils::{debug_code_string::QToCodeString, QPGenRandom},
};

pub const ZERO_HASH_CACHE_SIZE: usize = 128;
pub trait MerkleZeroHasherWithCache<Hash: PartialEq + Copy>: MerkleHasher<Hash> {
    const CACHED_ZERO_HASHES: [Hash; ZERO_HASH_CACHE_SIZE];
}

pub fn iterate_merkle_hasher<Hash: PartialEq, Hasher: MerkleHasher<Hash>>(mut current: Hash, reverse_level: usize) -> Hash {
    for _ in 0..reverse_level {
        current = Hasher::two_to_one(&current, &current);
    }
    current
}
pub fn generate_zero_hashes<Hash: PartialEq + Copy + ZeroableHash, Hasher: MerkleHasher<Hash>>() -> [Hash; ZERO_HASH_CACHE_SIZE] {
    let mut zero_hashes = [Hash::get_zero_value(); ZERO_HASH_CACHE_SIZE];
    zero_hashes[0] = Hash::get_zero_value();
    for i in 1..ZERO_HASH_CACHE_SIZE {
        zero_hashes[i] = Hasher::two_to_one(&zero_hashes[i - 1], &zero_hashes[i - 1]);
    }
    zero_hashes
}
pub fn generate_zero_hashes_code<Hash: PartialEq + CodeSerializableHash + ZeroableHash, Hasher: MerkleHasher<Hash>>() -> String {
    let zero_hashes = generate_zero_hashes::<Hash, Hasher>();
    let mut code_lines = vec![format!(
        "pub const CACHED_ZERO_HASHES: [<{}>; {}] = [",
        Hash::get_type_name(),
        ZERO_HASH_CACHE_SIZE
    )];
    for (_, zh) in zero_hashes.iter().enumerate() {
        code_lines.push(format!("    {},", zh.to_constant_code()));
    }
    code_lines.push("];".to_string());
    code_lines.join("\n")
}
impl<Hash: PartialEq + Copy, T: MerkleZeroHasherWithCache<Hash>> MerkleZeroHasher<Hash> for T {
    fn get_zero_hash(reverse_level: usize) -> Hash {
        if reverse_level < ZERO_HASH_CACHE_SIZE {
            T::CACHED_ZERO_HASHES[reverse_level]
        } else {
            let current = T::CACHED_ZERO_HASHES[ZERO_HASH_CACHE_SIZE - 1];
            iterate_merkle_hasher::<Hash, Self>(current, reverse_level - ZERO_HASH_CACHE_SIZE + 1)
        }
    }
}

pub fn compute_partial_merkle_root_from_leaves<Hash: PartialEq + Copy, Hasher: MerkleHasher<Hash>>(leaves: &[Hash]) -> Hash {
    let mut current = leaves.to_vec();
    while current.len() > 1 {
        let mut next = vec![];
        for i in 0..current.len() / 2 {
            next.push(Hasher::two_to_one(&current[2 * i], &current[2 * i + 1]));
        }
        if current.len() % 2 == 1 {
            next.push(current[current.len() - 1]);
        }
        current = next;
    }
    current[0]
}

pub fn compute_root_merkle_proof_generic<Hash, H: MerkleHasher<Hash>>(value: Hash, index: u64, siblings: &[Hash]) -> Hash {
    let mut current = value;
    for (i, sibling) in siblings.iter().enumerate() {
        if index & (1 << i) == 0 {
            current = H::two_to_one(&current, sibling);
        } else {
            current = H::two_to_one(sibling, &current);
        }
    }
    current
}


pub fn compute_path_merkle_proof_generic<Hash: Copy, H: MerkleHasher<Hash>>(value: Hash, mut index: u64, siblings: &[Hash]) -> Vec<Hash> {
    let mut current = value;
    let mut merkle_path = Vec::with_capacity(siblings.len() + 1);
    merkle_path.push(current);
    for sibling in siblings.iter(){
        current = H::two_to_one_swap((index&1) == 1, &current, sibling);
        merkle_path.push(current);
        index >>= 1;
    }
    merkle_path
}

pub fn verify_merkle_proof_core<Hash: PartialEq + Copy, Hasher: MerkleHasher<Hash>>(proof: &MerkleProofCore<Hash>) -> bool {
    if proof.siblings.len() > 64 {
        return false;
    }
    let mut current = proof.value;
    for (i, sibling) in proof.siblings.iter().enumerate() {
        if proof.index & (1 << i) == 0 {
            current = Hasher::two_to_one(&current, sibling);
        } else {
            current = Hasher::two_to_one(sibling, &current);
        }
    }
    current == proof.root
}

pub fn compute_historical_and_current_merkle_roots_core<Hash: PartialEq + Copy, Hasher: MerkleZeroHasher<Hash>>(
    proof: &MerkleProofCore<Hash>,
) -> (Hash, Hash) {
    let mut current = proof.value;
    let mut historical = Hasher::get_zero_hash(0);
    for (i, sibling) in proof.siblings.iter().enumerate() {
        if proof.index & (1 << i) == 0 {
            current = Hasher::two_to_one(&current, sibling);
            historical = Hasher::two_to_one(&historical, &Hasher::get_zero_hash(i));
        } else {
            current = Hasher::two_to_one(sibling, &current);
            historical = Hasher::two_to_one(sibling, &historical);
        }
    }
    (historical, current)
}

pub fn verify_delta_merkle_proof_core<Hash: PartialEq + Copy, Hasher: MerkleHasher<Hash>>(proof: &DeltaMerkleProofCore<Hash>) -> bool {
    if proof.siblings.len() > 64 {
        return false;
    }
    let mut current = proof.old_value;
    for (i, sibling) in proof.siblings.iter().enumerate() {
        if proof.index & (1 << i) == 0 {
            current = Hasher::two_to_one(&current, sibling);
        } else {
            current = Hasher::two_to_one(sibling, &current);
        }
    }
    if current != proof.old_root {
        return false;
    }
    current = proof.new_value;
    for (i, sibling) in proof.siblings.iter().enumerate() {
        if proof.index & (1 << i) == 0 {
            current = Hasher::two_to_one(&current, sibling);
        } else {
            current = Hasher::two_to_one(sibling, &current);
        }
    }
    current == proof.new_root
}

pub fn verify_delta_merkle_proof_core_debug<Hash: PartialEq + Copy + Serialize, Hasher: MerkleHasher<Hash>>(
    proof: &DeltaMerkleProofCore<Hash>,
) -> bool {
    println!("got delta merkle proof: {}", serde_json::to_string_pretty(proof).unwrap());

    if proof.siblings.len() > 64 {
        return false;
    }
    println!("starting old path");
    let mut current = proof.old_value;
    for (i, sibling) in proof.siblings.iter().enumerate() {
        println!(
            "at level {}, at index {}, current = {}, sibling = {}",
            i,
            proof.index >> i,
            serde_json::to_string(&current).unwrap(),
            serde_json::to_string(&sibling).unwrap()
        );
        if proof.index & (1 << i) == 0 {
            current = Hasher::two_to_one(&current, sibling);
        } else {
            current = Hasher::two_to_one(sibling, &current);
        }
        println!(
            "hash(swap = {}, left = {}, right = {}) = {}",
            proof.index & (1 << i) == 0,
            serde_json::to_string(&current).unwrap(),
            serde_json::to_string(&sibling).unwrap(),
            serde_json::to_string(&current).unwrap()
        );
    }
    if current != proof.old_root {
        println!(
            "failed old path verification: computed root {} but expected {}",
            serde_json::to_string(&current).unwrap(),
            serde_json::to_string(&proof.old_root).unwrap()
        );
        return false;
    }
    println!("verified old path");
    current = proof.new_value;
    for (i, sibling) in proof.siblings.iter().enumerate() {
        if proof.index & (1 << i) == 0 {
            current = Hasher::two_to_one(&current, sibling);
        } else {
            current = Hasher::two_to_one(sibling, &current);
        }
    }
    current == proof.new_root
}

pub fn calc_merkle_root_from_leaves<Hash: Copy, Hasher: MerkleHasher<Hash>>(leaves: &[Hash]) -> Hash {
    let mut current_leaves: Vec<Hash> = leaves.chunks_exact(2).map(|chunk| Hasher::two_to_one(&chunk[0], &chunk[1])).collect();
    let height = (current_leaves.len() as f64).log2().ceil() as usize;
    for _ in 1..height {
        let next_leaves = current_leaves
            .chunks_exact(2)
            .map(|chunk| Hasher::two_to_one(&chunk[0], &chunk[1]))
            .collect();
        current_leaves = next_leaves;
    }
    current_leaves[0]
}

pub fn compute_historical_and_current_merkle_roots_core_gt<Hash: Copy, Hasher: MerkleZeroHasher<Hash>>(
    proof: &MerkleProofCore<Hash>,
) -> (Hash, Hash) {
    let mut current = proof.value;
    let mut historical = current.clone();
    for (i, sibling) in proof.siblings.iter().enumerate() {
        if proof.index & (1 << i) == 0 {
            current = Hasher::two_to_one(&current, sibling);
            historical = Hasher::two_to_one(&historical, &Hasher::get_zero_hash(i));
        } else {
            current = Hasher::two_to_one(sibling, &current);
            historical = Hasher::two_to_one(sibling, &historical);
        }
    }
    (historical, current)
}

// Start Merkle Proof
#[pderive::serialize_clone]
#[derive(ts_rs::TS)]
#[ts(export)]
#[repr(C)]
pub struct MerkleProofCore<Hash> {
    pub root: Hash,
    pub value: Hash,

    pub index: u64,
    pub siblings: Vec<Hash>,
}
impl<Hash: QToCodeString> QToCodeString for MerkleProofCore<Hash> {
    fn to_debug_code_string(&self) -> String {
        format!(
            "MerkleProofCore {{ root: {}, value: {}, index: {}, siblings: vec![{}] }}",
            self.root.to_debug_code_string(),
            self.value.to_debug_code_string(),
            self.index,
            Hash::dbg_vec_of_self_to_debug_code_string(&self.siblings)
        )
    }
}
impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for MerkleProofCore<Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

pser::impl_psy_ser_basic_tests!(
    MerkleProofCore,
    // Note the use of concrete types here
    { crate::PHash },
    merkle_proof_core_tests,
    true
);
/*
impl<Hash: Q256BitHash> PsyIOReadWrite for MerkleProofCore<Hash> {
    fn pio_serialized_size(&self) -> usize {
        let sibling_size = self.siblings.len() * 32;
        4 + sibling_size + 2 * 32 + 8
    }

    fn pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.write_all(&self.root.into_owned_32bytes())?;
        writer.write_all(&self.value.into_owned_32bytes())?;
        writer.write_all(&self.index.to_le_bytes())?;
        let sibling_count = self.siblings.len() as u32;
        writer.write_all(&sibling_count.to_le_bytes())?;
        for sibling in &self.siblings {
            writer.write_all(&sibling.into_owned_32bytes())?;
        }
        Ok(())
    }

    fn pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let mut root_raw = [0u8; 32];
        reader.read_exact(&mut root_raw)?;
        let root = Q256BitHash::from_owned_32bytes(root_raw);
        let mut value_raw = [0u8; 32];
        reader.read_exact(&mut value_raw)?;
        let value = Q256BitHash::from_owned_32bytes(value_raw);
        let mut index_raw = [0u8; 8];
        reader.read_exact(&mut index_raw)?;
        let index = u64::from_le_bytes(index_raw);
        let mut sibling_count_raw = [0u8; 4];
        reader.read_exact(&mut sibling_count_raw)?;
        let sibling_count = u32::from_le_bytes(sibling_count_raw);
        let mut siblings = Vec::with_capacity(sibling_count as usize);
        for _ in 0..sibling_count {
            let mut sibling_raw = [0u8; 32];
            reader.read_exact(&mut sibling_raw)?;
            let sibling = Q256BitHash::from_owned_32bytes(sibling_raw);
            siblings.push(sibling);
        }
        Ok(Self {
            root,
            value,
            index,
            siblings,
        })
    }
}
impl<Hash: Q256BitHash> PsyCanonicalDatabaseSerializeBaseSingle for MerkleProofCore<Hash> {
    fn psy_ser_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() < (32+32+8+4) {
            anyhow::bail!("Data length {} is too small to contain MerkleProofCore", data.len());
        }
        let root = Q256BitHash::from_slice_32bytes(&data[0..32])?;
        let value = Q256BitHash::from_slice_32bytes(&data[32..64])?;
        let index = u64::from_le_bytes(data[64..72].try_into().unwrap());
        let sibling_count = u32::from_le_bytes(data[72..76].try_into().unwrap());
        let expected_len = 32 + 32 + 8 + 4 + (sibling_count as usize) * 32;
        if data.len() != expected_len {
            anyhow::bail!("Data length {} does not match expected length {} for MerkleProofCore with {} siblings", data.len(), expected_len, sibling_count);
        }
        let mut siblings = Vec::with_capacity(sibling_count as usize);
        for i in 0..sibling_count {
            let start = 76 + (i as usize) * 32;
            let end = start + 32;
            let sibling = Q256BitHash::from_slice_32bytes(&data[start..end])?;
            siblings.push(sibling);
        }
        Ok(Self {
            root,
            value,
            index,
            siblings,
        })

    }

    fn psy_ser_to_bytes_vec(&self) -> anyhow::Result<Vec<u8>> {
        let size = 32 + 32 + 8 + 4 + (self.siblings.len() * 32);
        let mut buf = Vec::with_capacity(size);
        buf.extend_from_slice(&self.root.into_owned_32bytes());
        buf.extend_from_slice(&self.value.into_owned_32bytes());
        buf.extend_from_slice(&self.index.to_le_bytes());
        let sibling_count = self.siblings.len() as u32;
        buf.extend_from_slice(&sibling_count.to_le_bytes());
        for sibling in &self.siblings {
            buf.extend_from_slice(&sibling.into_owned_32bytes());
        }
        Ok(buf)
    }
}
*/

impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for MerkleProofCore<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        32 + 32 + 8 + 4 + (self.siblings.len() * 32)
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.root.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.value.into_owned_32bytes())?;
        writer.psy_write_u64(self.index)?;
        writer.psy_write_vec_length(self.siblings.len())?;
        for sibling in &self.siblings {
            writer.psy_write_bytes_fixed(&sibling.into_owned_32bytes())?;
        }
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let root = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let value = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let index = reader.psy_read_u64()?;
        let sibling_count = reader.psy_read_vec_length()?;
        let mut siblings = Vec::with_capacity(sibling_count);
        for _ in 0..sibling_count {
            let sibling = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
            siblings.push(sibling);
        }
        Ok(Self {
            root,
            value,
            index,
            siblings,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
//#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    MerkleProofCore,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for MerkleProofCore<Hash> {}

impl<Hash: Default> Default for MerkleProofCore<Hash> {
    fn default() -> Self {
        Self {
            root: Default::default(),
            value: Default::default(),
            index: Default::default(),
            siblings: Default::default(),
        }
    }
}
impl<Hash: PartialEq + Copy> MerkleProofCore<Hash> {
    pub fn new_from_params<Hasher: MerkleHasher<Hash>>(index: u64, value: Hash, siblings: Vec<Hash>) -> Self {
        let root = compute_root_merkle_proof_generic::<Hash, Hasher>(value, index, &siblings);
        Self {
            root,
            value,
            index,
            siblings,
        }
    }
    pub fn verify<Hasher: MerkleHasher<Hash>>(&self) -> bool {
        if self.siblings.len() > 64 {
            return false;
        }
        verify_merkle_proof_core::<Hash, Hasher>(self)
    }
    pub fn to_delta_merkle_proof_template_inplace(self) -> DeltaMerkleProofCore<Hash> {
        DeltaMerkleProofCore {
            old_root: self.root,
            new_root: self.root,
            old_value: self.value,
            new_value: self.value,
            index: self.index,
            siblings: self.siblings,
        }
    }
    pub fn to_delta_merkle_proof_template(&self) -> DeltaMerkleProofCore<Hash> {
        DeltaMerkleProofCore {
            old_root: self.root,
            new_root: self.root,
            old_value: self.value,
            new_value: self.value,
            index: self.index,
            siblings: self.siblings.clone(),
        }
    }
}

#[cfg(feature = "rand")]
impl<Hash: QPGenRandom> QPGenRandom for MerkleProofCore<Hash> {
    fn qp_rand_gen() -> Self {
        Self {
            root: Hash::qp_rand_gen(),
            value: Hash::qp_rand_gen(),
            index: rand::random::<u64>(),
            siblings: Hash::qp_rand_gen_vec((rand::random::<u8>() & 63) as usize),
        }
    }
}

impl<Hash> QPDSerializable for MerkleProofCore<Hash>
where
    Hash: PartialEq + Copy + Serialize,
    for<'de2> Hash: Deserialize<'de2>,
{
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        self.to_qbytes()
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Self::from_qbytes(bytes)
    }
}

// Start Delta Merkle Proof

#[pderive::serialize_clone]
#[derive(ts_rs::TS)]
#[ts(export)]
pub struct DeltaMerkleProofCore<Hash> {
    pub old_root: Hash,
    pub old_value: Hash,

    pub new_root: Hash,
    pub new_value: Hash,

    pub index: u64,
    pub siblings: Vec<Hash>,
}

#[cfg(feature = "std")]
impl<Hash: QToCodeString> QToCodeString for DeltaMerkleProofCore<Hash> {
    fn to_debug_code_string(&self) -> String {
        format!(
            "DeltaMerkleProofCore {{ old_root: {}, old_value: {}, new_root: {}, new_value: {}, index: {}, siblings: {} }}",
            self.old_root.to_debug_code_string(),
            self.old_value.to_debug_code_string(),
            self.new_root.to_debug_code_string(),
            self.new_value.to_debug_code_string(),
            self.index,
            Hash::dbg_vec_of_self_to_debug_code_string(&self.siblings)
        )
    }
}

#[cfg(feature = "rand")]
impl<Hash: QPGenRandom> QPGenRandom for DeltaMerkleProofCore<Hash> {
    fn qp_rand_gen() -> Self {
        Self {
            old_value: Hash::qp_rand_gen(),
            new_value: Hash::qp_rand_gen(),
            old_root: Hash::qp_rand_gen(),
            new_root: Hash::qp_rand_gen(),
            index: rand::random::<u64>(),
            siblings: Hash::qp_rand_gen_vec((rand::random::<u8>() & 63) as usize),
        }
    }
}
impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for DeltaMerkleProofCore<Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}
impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for DeltaMerkleProofCore<Hash> {
    
    fn fallback_pio_serialized_size(&self) -> usize {
        32 + 32 + 32 + 32 + 8 + 4 + (self.siblings.len() * 32)
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.old_root.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.old_value.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.new_root.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.new_value.into_owned_32bytes())?;
        writer.psy_write_u64(self.index)?;
        writer.psy_write_vec_length(self.siblings.len())?;
        for sibling in &self.siblings {
            writer.psy_write_bytes_fixed(&sibling.into_owned_32bytes())?;
        }
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let old_root = Q256BitHash::from_slice_32bytes(&reader.psy_read_bytes_fixed::<32>()?)?;
        let old_value = Q256BitHash::from_slice_32bytes(&reader.psy_read_bytes_fixed::<32>()?)?;
        let new_root = Q256BitHash::from_slice_32bytes(&reader.psy_read_bytes_fixed::<32>()?)?;
        let new_value = Q256BitHash::from_slice_32bytes(&reader.psy_read_bytes_fixed::<32>()?)?;
        let index = reader.psy_read_u64()?;
        let sibling_count = reader.psy_read_vec_length()?;
        let mut siblings = Vec::with_capacity(sibling_count);
        for _ in 0..sibling_count {
            let sibling = Q256BitHash::from_slice_32bytes(&reader.psy_read_bytes_fixed::<32>()?)?;
            siblings.push(sibling);
        }
        Ok(Self {
            old_root,
            old_value,
            new_root,
            new_value,
            index,
            siblings,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
//#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    DeltaMerkleProofCore,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for DeltaMerkleProofCore<Hash> {}

impl<Hash: PartialEq + Copy> DeltaMerkleProofCore<Hash> {
    pub fn from_params<H: MerkleHasher<Hash>>(index: u64, old_value: Hash, new_value: Hash, siblings: Vec<Hash>) -> Self {
        let old_root = compute_root_merkle_proof_generic::<Hash, H>(old_value, index, &siblings);
        let new_root = compute_root_merkle_proof_generic::<Hash, H>(new_value, index, &siblings);

        Self {
            old_root,
            old_value,
            new_root,
            new_value,
            index,
            siblings,
        }
    }

    pub fn verify<Hasher: MerkleHasher<Hash>>(&self) -> bool {
        if self.siblings.len() > 64 {
            return false;
        }
        verify_delta_merkle_proof_core::<Hash, Hasher>(self)
    }

    pub fn single_value(index: u64, old_value: Hash, new_value: Hash) -> Self {
        Self {
            old_root: old_value,
            old_value,
            new_root: new_value,
            new_value,
            index,
            siblings: Vec::new(),
        }
    }

    pub fn with_shortened_height_from_bottom<H: MerkleHasher<Hash>>(&self, new_height: usize) -> Self {
        assert!(
            new_height <= self.siblings.len(),
            "cannot shorten tree to a height taller than the current proof"
        );
        if new_height == self.siblings.len() {
            self.clone()
        } else {
            let height_diff = self.siblings.len() - new_height;
            let low_index = self.index & ((1u64 << (height_diff as u64)) - 1u64);
            let new_index = self.index >> (height_diff as u64);
            let old_value = compute_root_merkle_proof_generic::<Hash, H>(self.old_value, low_index, &self.siblings[0..height_diff]);
            let new_value = compute_root_merkle_proof_generic::<Hash, H>(self.new_value, low_index, &self.siblings[0..height_diff]);

            Self::from_params::<H>(new_index, old_value, new_value, self.siblings[height_diff..].to_vec())
        }
    }

    pub fn shorten_height<H: MerkleHasher<Hash>>(&self, new_height: usize) -> Self {
        assert!(
            new_height <= self.siblings.len(),
            "cannot shorten tree to a height taller than the current proof"
        );
        if new_height == self.siblings.len() {
            self.clone()
        } else {
            Self::from_params::<H>(self.index, self.old_value, self.new_value, self.siblings[0..new_height].to_vec())
        }
    }
}
impl<Hash: PartialEq + Copy> From<MerkleProofCore<Hash>> for DeltaMerkleProofCore<Hash> {
    fn from(value: MerkleProofCore<Hash>) -> Self {
        Self {
            old_root: value.root,
            old_value: value.value,
            new_root: value.root,
            new_value: value.value,
            index: value.index,
            siblings: value.siblings,
        }
    }
}
impl<Hash: Copy> From<&MerkleProofCore<Hash>> for DeltaMerkleProofCore<Hash> {
    fn from(value: &MerkleProofCore<Hash>) -> Self {
        Self {
            old_root: value.root,
            old_value: value.value,
            new_root: value.root,
            new_value: value.value,
            index: value.index,
            siblings: value.siblings.clone(),
        }
    }
}
impl<Hash: Default> Default for DeltaMerkleProofCore<Hash> {
    fn default() -> Self {
        Self {
            old_root: Default::default(),
            old_value: Default::default(),
            new_root: Default::default(),
            new_value: Default::default(),
            index: Default::default(),
            siblings: Default::default(),
        }
    }
}
impl<Hash> QPDSerializable for DeltaMerkleProofCore<Hash>
where
    Hash: PartialEq + Copy + Serialize,
    for<'de2> Hash: Deserialize<'de2>,
{
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        self.to_qbytes()
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Self::from_qbytes(bytes)
    }
}

#[pderive::serialize_clone]
#[derive(ts_rs::TS)]
#[ts(export)]
pub struct DeltaMerkleProofCorePartial<Hash> {
    pub old_value: Hash,
    pub new_value: Hash,

    pub index: u64,
    pub siblings: Vec<Hash>,
}

#[cfg(feature = "rand")]
impl<Hash: QPGenRandom> QPGenRandom for DeltaMerkleProofCorePartial<Hash> {
    fn qp_rand_gen() -> Self {
        Self {
            old_value: Hash::qp_rand_gen(),
            new_value: Hash::qp_rand_gen(),
            index: rand::random::<u64>(),
            siblings: Hash::qp_rand_gen_vec((rand::random::<u8>() & 63) as usize),
        }
    }
}
#[cfg(test)]
mod tests {

    use crate::{utils::debug_code_string::get_psy_ser_test_cases_string, PHash};

    type Hash = PHash;
    use psy_serialize::*;

    fn test_auto<T: PsySerializeCanonicalAsyncSafe>(proof: &T){
        let serialized = proof.psy_ser_to_bytes_vec().unwrap();
        let deserialized = T::psy_ser_from_slice(&serialized).unwrap();
        let reserialized = deserialized.psy_ser_to_bytes_vec().unwrap();
        assert_eq!(serialized, reserialized);
    }

    use super::*;
    #[test]
    fn round_trip_canonical_serialization_merkle_proof_core() {
        let merkle_proofs = MerkleProofCore::<Hash>::qp_rand_gen_vec(12);
        for merkle_proof in merkle_proofs {
            let serialized = merkle_proof.psy_ser_to_bytes_vec().unwrap();
            let deserialized = MerkleProofCore::<Hash>::psy_ser_from_slice(&serialized).unwrap();
            assert_eq!(merkle_proof.root, deserialized.root);
            assert_eq!(merkle_proof.value, deserialized.value);
            assert_eq!(merkle_proof.index, deserialized.index);
            assert_eq!(merkle_proof.siblings.len(), deserialized.siblings.len());
            for (a, b) in merkle_proof.siblings.iter().zip(deserialized.siblings.iter()) {
                assert_eq!(*a, *b);
            }
        }
        let proof = MerkleProofCore::<Hash>::qp_rand_gen();
        test_auto(&proof);
    }

    #[ignore]
    #[test]
    fn gen_test_cases_dmp() {
        let mut test_cases = vec![
            DeltaMerkleProofCore {
                old_root: PHash::ZERO,
                old_value: PHash::ZERO,
                new_root: PHash::ZERO,
                new_value: PHash::ZERO,
                index: 0,
                siblings: vec![],
            },
            DeltaMerkleProofCore {
                old_root: PHash::ZERO,
                old_value: PHash::ZERO,
                new_root: PHash::ZERO,
                new_value: PHash::ZERO,
                index: 1,
                siblings: vec![],
            },
            DeltaMerkleProofCore {
                old_root: PHash::ZERO,
                old_value: PHash::ZERO,
                new_root: PHash::ZERO,
                new_value: PHash::ZERO,
                index: 0xffff,
                siblings: vec![],
            },
            DeltaMerkleProofCore {
                old_root: PHash::ZERO,
                old_value: PHash::ZERO,
                new_root: PHash::ZERO,
                new_value: PHash::ZERO,
                index: 0xffffffff,
                siblings: vec![],
            },
            DeltaMerkleProofCore {
                old_root: PHash::ZERO,
                old_value: PHash::ZERO,
                new_root: PHash::ZERO,
                new_value: PHash::ZERO,
                index: 0xffffffffABCDEF01u64,
                siblings: vec![],
            },
            DeltaMerkleProofCore {
                old_root: PHash::ZERO,
                old_value: PHash::ZERO,
                new_root: PHash::ZERO,
                new_value: PHash::ZERO,
                index: u64::MAX,
                siblings: vec![PHash::ZERO],
            },
            DeltaMerkleProofCore {
                old_root: PHash::ZERO,
                old_value: PHash::ZERO,
                new_root: PHash::ZERO,
                new_value: PHash::ZERO,
                index: u64::MAX,
                siblings: vec![PHash::ZERO; 127],
            },
            DeltaMerkleProofCore {
                old_root: PHash::ZERO,
                old_value: PHash::ZERO,
                new_root: PHash::ZERO,
                new_value: PHash::ZERO,
                index: 0,
                siblings: vec![PHash::ZERO; 20],
            },
            DeltaMerkleProofCore {
                old_root: PHash::ZERO,
                old_value: PHash::ZERO,
                new_root: PHash::ZERO,
                new_value: PHash::ZERO,
                index: u64::MAX,
                siblings: vec![PHash::ZERO, PHash::ZERO, PHash::ZERO],
            },
            DeltaMerkleProofCore {
                old_root: PHash::qp_rand_gen(),
                old_value: PHash::qp_rand_gen(),
                new_root: PHash::qp_rand_gen(),
                new_value: PHash::qp_rand_gen(),
                index: u64::MAX,
                siblings: vec![],
            },
            DeltaMerkleProofCore {
                old_root: PHash::qp_rand_gen(),
                old_value: PHash::qp_rand_gen(),
                new_root: PHash::qp_rand_gen(),
                new_value: PHash::qp_rand_gen(),
                index: u64::MAX,
                siblings: vec![],
            },
            DeltaMerkleProofCore {
                old_root: PHash::qp_rand_gen(),
                old_value: PHash::qp_rand_gen(),
                new_root: PHash::qp_rand_gen(),
                new_value: PHash::qp_rand_gen(),
                index: 0,
                siblings: vec![],
            },
            DeltaMerkleProofCore {
                old_root: PHash::qp_rand_gen(),
                old_value: PHash::qp_rand_gen(),
                new_root: PHash::qp_rand_gen(),
                new_value: PHash::qp_rand_gen(),
                index: u64::MAX,
                siblings: vec![PHash::qp_rand_gen()],
            },
            DeltaMerkleProofCore {
                old_root: PHash::qp_rand_gen(),
                old_value: PHash::qp_rand_gen(),
                new_root: PHash::qp_rand_gen(),
                new_value: PHash::qp_rand_gen(),
                index: 1337,
                siblings: vec![PHash::qp_rand_gen(), PHash::qp_rand_gen()],
            },
            DeltaMerkleProofCore {
                old_root: PHash::qp_rand_gen(),
                old_value: PHash::qp_rand_gen(),
                new_root: PHash::qp_rand_gen(),
                new_value: PHash::qp_rand_gen(),
                index: 0,
                siblings: vec![PHash::qp_rand_gen(), PHash::qp_rand_gen(), PHash::qp_rand_gen()],
            },
            DeltaMerkleProofCore {
                old_root: PHash::qp_rand_gen(),
                old_value: PHash::ZERO,
                new_root: PHash::qp_rand_gen(),
                new_value: PHash::ZERO,
                index: 0,
                siblings: vec![PHash::qp_rand_gen()],
            },
            DeltaMerkleProofCore {
                old_root: PHash::from_values(1, 2, 3, 4),
                old_value: PHash::from_values(5, 6, 7, 8),
                new_root: PHash::from_values(9, 10, 11, 12),
                new_value: PHash::from_values(13, 14, 15, 16),
                index: 1,
                siblings: vec![PHash::from_values(9, 10, 11, 12)],
            },
            DeltaMerkleProofCore {
                old_root: PHash::from_values(1, 2, 3, 4),
                old_value: PHash::from_values(5, 6, 7, 8),
                new_root: PHash::from_values(9, 10, 11, 12),
                new_value: PHash::from_values(13, 14, 15, 16),
                index: 13376969,
                siblings: vec![PHash::from_values(9, 10, 11, 12)],
            },
            DeltaMerkleProofCore {
                old_root: PHash::qp_rand_gen(),
                old_value: PHash::qp_rand_gen(),
                new_root: PHash::qp_rand_gen(),
                new_value: PHash::qp_rand_gen(),
                index: 0,
                siblings: vec![PHash::qp_rand_gen()],
            },
            DeltaMerkleProofCore {
                old_root: PHash::qp_rand_gen(),
                old_value: PHash::qp_rand_gen(),
                new_root: PHash::qp_rand_gen(),
                new_value: PHash::qp_rand_gen(),
                index: 0xff,
                siblings: vec![PHash::qp_rand_gen()],
            },
            DeltaMerkleProofCore {
                old_root: PHash::qp_rand_gen(),
                old_value: PHash::qp_rand_gen(),
                new_root: PHash::qp_rand_gen(),
                new_value: PHash::qp_rand_gen(),
                index: 0xffff,
                siblings: vec![PHash::qp_rand_gen()],
            },
            DeltaMerkleProofCore {
                old_root: PHash::qp_rand_gen(),
                old_value: PHash::qp_rand_gen(),
                new_root: PHash::qp_rand_gen(),
                new_value: PHash::qp_rand_gen(),
                index: 0xffffff,
                siblings: vec![PHash::qp_rand_gen()],
            },
            DeltaMerkleProofCore {
                old_root: PHash::qp_rand_gen(),
                old_value: PHash::qp_rand_gen(),
                new_root: PHash::qp_rand_gen(),
                new_value: PHash::qp_rand_gen(),
                index: 0xffffffff,
                siblings: vec![PHash::qp_rand_gen()],
            },
            DeltaMerkleProofCore {
                old_root: PHash::qp_rand_gen(),
                old_value: PHash::qp_rand_gen(),
                new_root: PHash::qp_rand_gen(),
                new_value: PHash::qp_rand_gen(),
                index: 0xffffffffffu64,
                siblings: vec![PHash::qp_rand_gen()],
            },
            DeltaMerkleProofCore {
                old_root: PHash::qp_rand_gen(),
                old_value: PHash::qp_rand_gen(),
                new_root: PHash::qp_rand_gen(),
                new_value: PHash::qp_rand_gen(),
                index: 0xffffffffffffu64,
                siblings: vec![PHash::qp_rand_gen()],
            },
            DeltaMerkleProofCore {
                old_root: PHash::qp_rand_gen(),
                old_value: PHash::qp_rand_gen(),
                new_root: PHash::qp_rand_gen(),
                new_value: PHash::qp_rand_gen(),
                index: 0xffffffffffffffu64,
                siblings: vec![PHash::qp_rand_gen()],
            },
            DeltaMerkleProofCore {
                old_root: PHash::qp_rand_gen(),
                old_value: PHash::qp_rand_gen(),
                new_root: PHash::qp_rand_gen(),
                new_value: PHash::qp_rand_gen(),
                index: 0xffffffffffffffffu64,
                siblings: vec![PHash::qp_rand_gen()],
            },
        ];
        test_cases.extend_from_slice(&QPGenRandom::qp_rand_gen_vec(16));
        println!("test_cases: \n{}\n", get_psy_ser_test_cases_string(&test_cases));

        let vec_ex = DeltaMerkleProofCore::<PHash>::qp_rand_gen_vec(1);
        let ser_vec = DeltaMerkleProofCore::<PHash>::psy_ser_serialize_vec_of_self_ref(&vec_ex, false);
        println!("vec_ser: {}", hex::encode(&ser_vec));
        let de_vec = DeltaMerkleProofCore::<PHash>::psy_ser_deserialize_vec_of_self(&ser_vec, false).unwrap();
        assert!(vec_ex == de_vec);
        assert_eq!(vec_ex.len(), de_vec.len());
        for (a, b) in vec_ex.iter().zip(de_vec.iter()) {
            assert_eq!(a.old_root, b.old_root);
            assert_eq!(a.old_value, b.old_value);
            assert_eq!(a.new_root, b.new_root);
            assert_eq!(a.new_value, b.new_value);
            assert_eq!(a.index, b.index);
        }
    }

    #[test]
    fn check_serialize_deserialize_many_mp() {
        let merkle_proofs = vec![
            MerkleProofCore {
                root: PHash::ZERO,
                value: PHash::ZERO,
                index: 0,
                siblings: vec![],
            },
            MerkleProofCore {
                root: PHash::ZERO,
                value: PHash::ZERO,
                index: 1,
                siblings: vec![PHash::from_values(1,2,3,4), PHash::from_values(5,6,7,8), PHash::from_values(9,10,11,12)],
            },
        ];
        let ser_vec = MerkleProofCore::<PHash>::psy_ser_serialize_vec_of_self_ref(&merkle_proofs, true);
        assert_eq!(ser_vec, hex_literal::hex!("0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000030000000100000000000000020000000000000003000000000000000400000000000000050000000000000006000000000000000700000000000000080000000000000009000000000000000a000000000000000b000000000000000c00000000000000"));
        
        let de_vec = MerkleProofCore::<PHash>::psy_ser_deserialize_vec_of_self(&ser_vec, true).unwrap();
        assert!(merkle_proofs == de_vec);

    }
    #[ignore]
    #[test]
    fn gen_test_cases() {
        let mut test_cases = vec![
            MerkleProofCore {
                root: PHash::ZERO,
                value: PHash::ZERO,
                index: 0,
                siblings: vec![],
            },
            MerkleProofCore {
                root: PHash::ZERO,
                value: PHash::ZERO,
                index: 1,
                siblings: vec![],
            },
            MerkleProofCore {
                root: PHash::ZERO,
                value: PHash::ZERO,
                index: 0xffff,
                siblings: vec![],
            },
            MerkleProofCore {
                root: PHash::ZERO,
                value: PHash::ZERO,
                index: 0xffffffff,
                siblings: vec![],
            },
            MerkleProofCore {
                root: PHash::ZERO,
                value: PHash::ZERO,
                index: 0xffffffffABCDEF01u64,
                siblings: vec![],
            },
            MerkleProofCore {
                root: PHash::ZERO,
                value: PHash::ZERO,
                index: u64::MAX,
                siblings: vec![PHash::ZERO],
            },
            MerkleProofCore {
                root: PHash::ZERO,
                value: PHash::ZERO,
                index: u64::MAX,
                siblings: vec![PHash::ZERO; 127],
            },
            MerkleProofCore {
                root: PHash::ZERO,
                value: PHash::ZERO,
                index: 0,
                siblings: vec![PHash::ZERO; 20],
            },
            MerkleProofCore {
                root: PHash::ZERO,
                value: PHash::ZERO,
                index: u64::MAX,
                siblings: vec![PHash::ZERO, PHash::ZERO, PHash::ZERO],
            },
            MerkleProofCore {
                root: PHash::qp_rand_gen(),
                value: PHash::qp_rand_gen(),
                index: u64::MAX,
                siblings: vec![],
            },
            MerkleProofCore {
                root: PHash::qp_rand_gen(),
                value: PHash::qp_rand_gen(),
                index: 1337,
                siblings: vec![],
            },
            MerkleProofCore {
                root: PHash::qp_rand_gen(),
                value: PHash::qp_rand_gen(),
                index: 0,
                siblings: vec![],
            },
            MerkleProofCore {
                root: PHash::qp_rand_gen(),
                value: PHash::qp_rand_gen(),
                index: u64::MAX,
                siblings: vec![PHash::qp_rand_gen()],
            },
            MerkleProofCore {
                root: PHash::qp_rand_gen(),
                value: PHash::qp_rand_gen(),
                index: 1337,
                siblings: vec![PHash::qp_rand_gen(), PHash::qp_rand_gen()],
            },
            MerkleProofCore {
                root: PHash::qp_rand_gen(),
                value: PHash::qp_rand_gen(),
                index: 0,
                siblings: vec![PHash::qp_rand_gen(), PHash::qp_rand_gen(), PHash::qp_rand_gen()],
            },
            MerkleProofCore {
                root: PHash::qp_rand_gen(),
                value: PHash::ZERO,
                index: 0,
                siblings: vec![PHash::qp_rand_gen()],
            },
            MerkleProofCore {
                root: PHash::from_values(1, 2, 3, 4),
                value: PHash::from_values(5, 6, 7, 8),
                index: 1,
                siblings: vec![PHash::from_values(9, 10, 11, 12)],
            },
            MerkleProofCore {
                root: PHash::from_values(1, 2, 3, 4),
                value: PHash::from_values(5, 6, 7, 8),
                index: 13376969,
                siblings: vec![PHash::from_values(9, 10, 11, 12)],
            },
            MerkleProofCore {
                root: PHash::qp_rand_gen(),
                value: PHash::qp_rand_gen(),
                index: 0,
                siblings: vec![PHash::qp_rand_gen()],
            },
            MerkleProofCore {
                root: PHash::qp_rand_gen(),
                value: PHash::qp_rand_gen(),
                index: 0xff,
                siblings: vec![PHash::qp_rand_gen()],
            },
            MerkleProofCore {
                root: PHash::qp_rand_gen(),
                value: PHash::qp_rand_gen(),
                index: 0xffff,
                siblings: vec![PHash::qp_rand_gen()],
            },
            MerkleProofCore {
                root: PHash::qp_rand_gen(),
                value: PHash::qp_rand_gen(),
                index: 0xffffff,
                siblings: vec![PHash::qp_rand_gen()],
            },
            MerkleProofCore {
                root: PHash::qp_rand_gen(),
                value: PHash::qp_rand_gen(),
                index: 0xffffffff,
                siblings: vec![PHash::qp_rand_gen()],
            },
            MerkleProofCore {
                root: PHash::qp_rand_gen(),
                value: PHash::qp_rand_gen(),
                index: 0xffffffffffu64,
                siblings: vec![PHash::qp_rand_gen()],
            },
            MerkleProofCore {
                root: PHash::qp_rand_gen(),
                value: PHash::qp_rand_gen(),
                index: 0xffffffffffffu64,
                siblings: vec![PHash::qp_rand_gen()],
            },
            MerkleProofCore {
                root: PHash::qp_rand_gen(),
                value: PHash::qp_rand_gen(),
                index: 0xffffffffffffffu64,
                siblings: vec![PHash::qp_rand_gen()],
            },
            MerkleProofCore {
                root: PHash::qp_rand_gen(),
                value: PHash::qp_rand_gen(),
                index: 0xffffffffffffffffu64,
                siblings: vec![PHash::qp_rand_gen()],
            },
        ];
        test_cases.extend_from_slice(&QPGenRandom::qp_rand_gen_vec(16));
        println!("test_cases: \n{}\n", get_psy_ser_test_cases_string(&test_cases));
    }

    fn check_test_case(item: &MerkleProofCore<Hash>, expected_serialized: &[u8]) {
        let original = item.clone();
        let serialized = item.psy_ser_to_bytes_vec().unwrap();
        assert_eq!(serialized, expected_serialized, "serialized does not match expected");
        let deserialized = MerkleProofCore::<Hash>::psy_ser_from_slice(&serialized).unwrap();
        assert!(original == deserialized, "original and deserialized do not match for merkle proof");

        let fallback_serialized = item.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(serialized, fallback_serialized, "serialized and fallback serialized do not match");
        let fallback_deserialized = MerkleProofCore::<Hash>::fallback_psy_ser_from_slice(&fallback_serialized).unwrap();
        assert!(
            original == fallback_deserialized,
            "original and fallback deserialized do not match:\noriginal: {}\ndeserialized: {}",
            original.to_debug_code_string(),
            fallback_deserialized.to_debug_code_string()
        );

        assert_eq!(item.root, deserialized.root);
        assert_eq!(item.value, deserialized.value);
        assert_eq!(item.index, deserialized.index);
        assert_eq!(item.siblings.len(), deserialized.siblings.len());
        for (a, b) in item.siblings.iter().zip(deserialized.siblings.iter()) {
            assert_eq!(*a, *b);
        }
    }
    fn check_test_case_dmp(item: &DeltaMerkleProofCore<Hash>, expected_serialized: &[u8]) {
        let original = item.clone();
        let serialized = item.psy_ser_to_bytes_vec().unwrap();
        assert_eq!(serialized, expected_serialized, "serialized does not match expected");
        let deserialized = DeltaMerkleProofCore::<Hash>::psy_ser_from_slice(&serialized).unwrap();
        assert!(original == deserialized, "original and deserialized do not match for merkle proof");

        let fallback_serialized = item.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(serialized, fallback_serialized, "serialized and fallback serialized do not match");
        let fallback_deserialized = DeltaMerkleProofCore::<Hash>::fallback_psy_ser_from_slice(&fallback_serialized).unwrap();
        assert!(original == fallback_deserialized, "original and fallback deserialized do not match");

        assert_eq!(item.old_root, deserialized.old_root);
        assert_eq!(item.new_root, deserialized.new_root);
        assert_eq!(item.old_value, deserialized.old_value);
        assert_eq!(item.new_value, deserialized.new_value);
        assert_eq!(item.index, deserialized.index);
        assert_eq!(item.siblings.len(), deserialized.siblings.len());
        for (a, b) in item.siblings.iter().zip(deserialized.siblings.iter()) {
            assert_eq!(*a, *b);
        }
    }
    #[test]
    fn check_canonical_serialization_delta_merkle_proof_core() {
        let test_cases = vec![
            (DeltaMerkleProofCore { old_root: PHash::ZERO, old_value: PHash::ZERO, new_root: PHash::ZERO, new_value: PHash::ZERO, index: 0, siblings: vec![] }, "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
            (DeltaMerkleProofCore { old_root: PHash::ZERO, old_value: PHash::ZERO, new_root: PHash::ZERO, new_value: PHash::ZERO, index: 1, siblings: vec![] }, "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000"),
            (DeltaMerkleProofCore { old_root: PHash::ZERO, old_value: PHash::ZERO, new_root: PHash::ZERO, new_value: PHash::ZERO, index: 65535, siblings: vec![] }, "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffff00000000000000000000"),
            (DeltaMerkleProofCore { old_root: PHash::ZERO, old_value: PHash::ZERO, new_root: PHash::ZERO, new_value: PHash::ZERO, index: 4294967295, siblings: vec![] }, "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0000000000000000"),
            (DeltaMerkleProofCore { old_root: PHash::ZERO, old_value: PHash::ZERO, new_root: PHash::ZERO, new_value: PHash::ZERO, index: 18446744072296984321, siblings: vec![] }, "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001efcdabffffffff00000000"),
            (DeltaMerkleProofCore { old_root: PHash::ZERO, old_value: PHash::ZERO, new_root: PHash::ZERO, new_value: PHash::ZERO, index: 18446744073709551615, siblings: vec![PHash::ZERO] }, "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffff010000000000000000000000000000000000000000000000000000000000000000000000"),
            (DeltaMerkleProofCore { old_root: PHash::ZERO, old_value: PHash::ZERO, new_root: PHash::ZERO, new_value: PHash::ZERO, index: 18446744073709551615, siblings: vec![PHash::ZERO; 127] }, "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
            (DeltaMerkleProofCore { old_root: PHash::ZERO, old_value: PHash::ZERO, new_root: PHash::ZERO, new_value: PHash::ZERO, index: 0, siblings: vec![PHash::ZERO; 20] }, "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
            (DeltaMerkleProofCore { old_root: PHash::ZERO, old_value: PHash::ZERO, new_root: PHash::ZERO, new_value: PHash::ZERO, index: 18446744073709551615, siblings: vec![PHash::ZERO; 3] }, "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffff03000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(17750111788297755504, 13857776815142125780, 1066391883804819812, 13504935222356399381), old_value: PHash::from_values(16697325137720994165, 472099751376794296, 17581484240889581117, 17731684302738514879), new_root: PHash::from_values(5343321788143412156, 8277312448405159241, 7095700713356055097, 8698955989509789545), new_value: PHash::from_values(17698351464745601169, 4242026718428248367, 10514053654492688778, 5204563611205297824), index: 18446744073709551615, siblings: vec![] }, "701bf698a01055f6d4c0307b97b650c064c18bb1c495cc0e15d53653082b6bbb75690f1dbfd0b8e7b8325dfb383c8d063d0e5a32c4fafdf3bf631946ed9813f6bca3e42edb4a274a49bd1b16d1ebde7239d2124434fe786269d77c2762e6b87891082d26e32c9df52fb9a13fd3b4de3a8a316fc9176ce991a0e6d08807533a48ffffffffffffffff00000000"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(6734632559154482405, 630245347929009347, 15318933682720673976, 10572296792325087666), old_value: PHash::from_values(16418351365245023655, 9711701576655733262, 6733208451513132596, 1711554857482824494), new_root: PHash::from_values(9172116911139393082, 9673345026162474098, 12012086882152054218, 17828167527648428573), new_value: PHash::from_values(7673450071852966117, 4312630534985937654, 17623438596627719685, 1657947582771149460), index: 18446744073709551615, siblings: vec![] }, "e5cc2e85a138765dc3aca604ce14bf08b810557005c997d4b2e1890eeb57b892a7b5fa1a94b3d9e30e822a1121e5c6863426199f6929715d2eabdb1d13aac0173a0ed116bce7497f72bc34ba0ca03e86ca7dcd656081b3a61d82a3a1e85f6af7e5e07d462f927d6af6f2564d9f8ad93b0566e7d8070893f494ba4ad78a360217ffffffffffffffff00000000"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(2094577512936816453, 9252184161513328973, 16809664030601637786, 9436465006563533818), old_value: PHash::from_values(7132313492636467822, 13864157604664081689, 9742650166703493013, 14388708910480029610), new_root: PHash::from_values(7048237042578391784, 6501425461235365783, 18253337989138729604, 12638032509679566639), new_value: PHash::from_values(8059296758383177574, 15478994505348830774, 17079583985354442620, 11694664476150388377), index: 0, siblings: vec![] }, "45bf1e85266f111d4d517f87795c66809aefabd95fec47e9faa39f4bed0ef5826e82523b5511fb62197d08d0e26167c0950f4335b5d83487aaf7a8f984f6aec7e882a23f3f5ed06197379dce02b4395a84cac1d730e250fd2fff49bf9b4f63af66efe2a6b35fd86f36568acb7d6fd0d67c8780a624df06ed99d6524c61cb4ba2000000000000000000000000"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(788247502533895893, 18307307803129606903, 16462613522410597674, 15664258592398248711), old_value: PHash::from_values(5019625630994518299, 5439963716057340462, 1663648439262817342, 7393718974318506193), new_root: PHash::from_values(7254271961019809060, 1223624873795248662, 8563536179797073130, 10513673189274043325), new_value: PHash::from_values(9333062158730681226, 14761325528277296335, 6306296991116172899, 5366125768226559096), index: 18446744073709551615, siblings: vec![PHash::from_values(15240100326092524908, 345630634773846191, 16092837198035047216, 4445644129007856094)] }, "d5269f5fed6af00af7f2465f739f10fe2a6dd3a5c6f376e4070bc26d32a062d91bd1df90ea4aa9452e9a9c762da27e4b3eac64ed70771617d1f051c93bc49b66247da9ece959ac6416e2e5f45630fb10ea9c02b2c8cad776bd433ad30f12e8918a5bc8ad95b28581cfa4dfee5bc3dacc631e9883b377845778d4368bf44e784affffffffffffffff010000006c4d0f4680b67fd3af1830293bedcb04305312092b3e55dfde695003c819b23d"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(4178567639104634289, 3195691939461730172, 4977373443123118145, 12888147726814520318), old_value: PHash::from_values(3370356326954680215, 13344371634343076066, 3428971855038885850, 1516078430783335074), new_root: PHash::from_values(13478491963047394121, 13000031095999162774, 5601339437771272761, 5694242643236980598), new_value: PHash::from_values(13428674674832629933, 8620366134473248681, 1881946737010796968, 8148231980043150055), index: 1337, siblings: vec![
            PHash::from_values(1442684354600199482, 8544027820547315530, 14439104089036989462, 5706046572007134736),
            PHash::from_values(3542096899249204583, 16254809417483260474, 5766045478696362040, 8350787152855500168)
        ] }, "b13dc6f62041fd397c0f322fe360592c4100d177c62e1345fea389bd12e6dbb297bf9ff238e9c52ee260d1c74cbb30b9daaf6714bc27962fa2ea78de4c310a1549bb653d07390dbb96e90f9a676369b43932be9e8af4bb4d768705bf8303064fade0aef5773c5cbaa9cf159f53b1a177a8e9bb1996041e1ae722f38dd05514713905000000000000020000003a65f5dec67105144a17c7da087c927616a4f0d5aa0062c81016521420f32f4f67edc2ef5c0e28313a92c3240baf94e138a07124d01b05508805d9d0abf4e373"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(5101906400342912085, 3622350160533117164, 2316335389461834792, 14691423453862204085), old_value: PHash::from_values(13909009587229671020, 15947504047760858156, 4810371604857923262, 4072948540269648526), new_root: PHash::from_values(5681882409614435944, 166735855044798870, 7836759288860235179, 770376865084726255), new_value: PHash::from_values(11062466897937295716, 15713914544418519986, 15167224588604157539, 1801312355234624260), index: 0, siblings: vec![
            PHash::from_values(7526844055661857463, 10087121307044514643, 11431463659373130316, 17067659984247715986),
            PHash::from_values(10671758268189310839, 9092594421269454589, 5876626668210724634, 12558645779146519045),
            PHash::from_values(16221599677384976994, 254544525357924527, 2662706560032427416, 11804250597906614618)
        ] }, "552cbb0dd79ccd46ecd8a76a472c453228ec89a5c3462520b5924cf4ca6be2cb6cbe53c886ba06c12cdce31c70ea50ddbea62ef97cdfc1428eda37331e05863868e69b98f219da4e96294473605d5002abd5c1620dc3c16cefdb8d5aadedb00a64e9113f08c78599b2fbe8b2050a13da632e526867ce7cd2043348170b8cff18000000000000000003000000b74a7c29cab87468538ba98862a7fc8b4cf2b8b7a1b7a49e92f83bcc5382dcec77ff42809ab31994fdde769673622f7e1a9f49acd1f88d5105b2fc2dcc4549ae626a1ffbf5b21ee1afc07aade552880398cdd53b82d5f3245a89ea8f601fd1a3"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(8650460622981548898, 17384432765643991881, 11572431901244858680, 10199962982116323538), old_value: PHash::ZERO, new_root: PHash::from_values(13579815058574305582, 1888214878102691007, 16061664545762869295, 6438890712978942817), new_value: PHash::ZERO, index: 0, siblings: vec![PHash::from_values(10003572240985275826, 15445460487908432747, 3183229784334090213, 9937890774917891194)] }, "62cb51c01a9c0c78492bdf617ee941f138211935808999a0d2702d5f4a8c8d8d00000000000000000000000000000000000000000000000000000000000000002e69d2c9d83175bcbf1ceb6c6d49341a2f80ae57ce7ee6de61ebab1efd885b590000000000000000000000000000000000000000000000000000000000000000000000000000000001000000b2bde2b4f3d3d38a6b1b1dee7a4c59d6e53fad959f1a2d2c7ac49caf017bea89"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(1, 2, 3, 4), old_value: PHash::from_values(5, 6, 7, 8), new_root: PHash::from_values(9, 10, 11, 12), new_value: PHash::from_values(13, 14, 15, 16), index: 1, siblings: vec![PHash::from_values(9, 10, 11, 12)] }, "0100000000000000020000000000000003000000000000000400000000000000050000000000000006000000000000000700000000000000080000000000000009000000000000000a000000000000000b000000000000000c000000000000000d000000000000000e000000000000000f00000000000000100000000000000001000000000000000100000009000000000000000a000000000000000b000000000000000c00000000000000"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(1, 2, 3, 4), old_value: PHash::from_values(5, 6, 7, 8), new_root: PHash::from_values(9, 10, 11, 12), new_value: PHash::from_values(13, 14, 15, 16), index: 13376969, siblings: vec![PHash::from_values(9, 10, 11, 12)] }, "0100000000000000020000000000000003000000000000000400000000000000050000000000000006000000000000000700000000000000080000000000000009000000000000000a000000000000000b000000000000000c000000000000000d000000000000000e000000000000000f000000000000001000000000000000c91dcc00000000000100000009000000000000000a000000000000000b000000000000000c00000000000000"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(2825453048658047182, 17407999669027593270, 10459395391300046522, 13073606891135216073), old_value: PHash::from_values(13130151591543471194, 470333504725706257, 2857437544970996874, 8672508513720666309), new_root: PHash::from_values(249319262183440355, 1233813522581952304, 6892617184644276807, 2931697499946591809), new_value: PHash::from_values(4590430621918182327, 3905415155798619908, 7043299999654347421, 7846300649660405271), index: 0, siblings: vec![PHash::from_values(17715899048193333373, 15147761946077920056, 1749181102327901110, 5589115225749115932)] }, "ceb0ceee9306362736dc81aa77a395f1ba0ecc2fb13c2791c9a9365733c86eb55a7cfa544eab37b611e623a3d4f586068a4cdccb4ea8a727c508df578bf05a78e33f1b4a8cc275033017929cdc621f1147a2798fcf7ea75f41a637e9577baf28b73b8259547cb43f04b7cd7564d232369d02e85d08d4be6117d6ec8fdea8e36c0000000000000000010000007d983e4c5284dbf5387b27d23ba937d2b6ab14ecf15646181cd48077af86904d"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(17201130395720473742, 67471747973444278, 17556014755527446191, 14126248485953700841), old_value: PHash::from_values(4677572595291942127, 3258934552400664096, 12036254184627670699, 1997316608932143249), new_root: PHash::from_values(18084064442990888344, 15658352064288662376, 6661686453881101772, 12645637160693966268), new_value: PHash::from_values(7340167752061907457, 15549856941549278338, 16598917567946873309, 17624216429972024099), index: 255, siblings: vec![PHash::from_values(16546517426101759374, 11035950535106615624, 1672093073649119514, 9449318457288074145)] }, "8edc179cf5b0b6eeb6f2548232b5ef00afceba86677ea3f3e9832b6627840ac4ef6c7a197e13ea4020961676b50f3a2dab8e0afd685d09a7916063a3dfe4b71b9885be23cc80f7fa6823eeaf3da44dd9cc5d9de08810735cbca5a489ff537eaf01726d3dae83dd6582d42f6d8030ccd7ddd9764d95335be623eb154977cb95f4ff00000000000000010000008e2d9b8cee09a1e548d9cf6b8a9227991a313f96ca773417a1a3328012b92283"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(1870226513910868420, 17128178653290058504, 12320803111072901368, 4047205531024991543), old_value: PHash::from_values(11596643458358516617, 9946719082624888957, 3805338548797334158, 15938783946635754112), new_root: PHash::from_values(16959339176640575080, 12915991095723841182, 5583689170940616771, 14920065919621090235), new_value: PHash::from_values(12531670456527154593, 6616070730776761977, 17764303869366696124, 535631188320512804), index: 65535, siblings: vec![PHash::from_values(3187413563793461518, 12112406297924249953, 17125279723610174431, 4622720645161222247)] }, "c4a92c031b61f4190853c876bc83b3edf82807af2649fcaa37a5bdc9fc8f2a38891b51a2c88defa07db074404ed8098a8e622aa33f47cf34803aec5a8def31dd68f6067120ad5beb9e56ba3e78d13eb343601ca2b73f7d4dbb4b6d6ce7b80ecfa1ed8e73e26fe9ad79d6ceb44601d15bbcf8b2f73f7c87f624eb7656baf16e07ffff000000000000010000000ed12ba6bff73b2c61a9fa8a5ae917a8dff3fbcc2c37a9ed6700b33eef332740"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(13491235580175785131, 11739052231013326115, 18406233062211468195, 7407614339711007860), old_value: PHash::from_values(2347467595305103368, 9070874191037128930, 12791229607567250149, 10961335258680950598), new_root: PHash::from_values(4634700188416099247, 3052049032057259603, 6119237233006156350, 15958393536950183797), new_value: PHash::from_values(12122694672165266124, 3762434269744091043, 10474889061761109792, 9257297953372746962), index: 16777215, siblings: vec![PHash::from_values(6011465804357878190, 3104008257053911742, 3920682923033465595, 4807477378537869193)] }, "ab1c7dd1477f3abb235d4ed5ce7de9a2a33b2a1e731370ff747c90a7fe21cd6608b0e62b57e19320e2e006670438e27de55281a78e9383b1467fa495577c1e98af43fa0244c351405306d9986c0e5b2a3e1aada1d7e5eb547527cee35e9a77ddcc62ee5693763ca8a34fdaba08da3634204fe5731a485e91d2b4bbfa70877880ffffff000000000001000000aec128884c046d53beea936510a7132bfb9259885810693689cf79653497b742"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(14534521507370768000, 564908068909657785, 12253190985521875993, 9404408087572691826), old_value: PHash::from_values(18247180468795124496, 17976935615770456789, 11750207893683701914, 5290470567086169887), new_root: PHash::from_values(6145554015849242632, 3936524051904899692, 14358171040910019075, 16068594182839501673), new_value: PHash::from_values(14435274731648974256, 3568752706962581477, 2904152583424899623, 16542478879986196455), index: 4294967295, siblings: vec![PHash::from_values(12050598861376485414, 8915312664384614804, 4250120386455939168, 6904396274536805571)] }, "80161cc34dfeb4c9b9ae1c4ae5f4d60719cc0cf947140caa72bb9436542b838210abfa6af5013bfdd5f21058b2e77af99a0802f4d21f11a31f9fd45df3866b490860ab1ed16449556caa92c3c457a136030abe257d7842c769830e34461dffdeb0fd1b17e36554c8e5e7b7cdadc1863127fa9244639f4d28e79ffa41e5b092e5ffffffff00000000010000002678124fd1533ca794b12f06a28db97b60285a2ff975fb3ac3f44ba4d457d15f"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(1515185902054214133, 9517471614586741145, 15013712665700750438, 12134334686489013092), old_value: PHash::from_values(10744442959082032617, 10404626148501366214, 16644927301597077763, 737997985660981434), new_root: PHash::from_values(4560905823813880728, 11156241959861618173, 7373025409499069618, 1739818715283480233), new_value: PHash::from_values(353173035932587317, 7917438306149108049, 2212630937411115176, 14483880608490852119), index: 1099511627775, siblings: vec![PHash::from_values(9503973097067591723, 11876620245437630033, 5014092425653051215, 7381707884548199402)] }, "f5099fd48c05071599614efb01da14846654e0961f6c5bd064ebe05d1bd165a8e90d88ddf1ed1b95c6252a225ba864900321e53331a9fee6bad0460442e53d0a98cb6f9aae974b3ffd05dc45f4eed29ab2fc1ec58b3f5266a95e0c52e71325183515024701b9e604518916e93064e06da8d86d531dd8b41e170f44aeac1401c9ffffffffff000000010000002b3895752de5e48351c6852d303bd2a44fdf06ce7ea29545ea13320636187166"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(7893887703575515252, 14347354299146352937, 13287860467367197165, 15236224297511609569), old_value: PHash::from_values(5460584510576756942, 13126955652788811571, 6360245822815508102, 14592559454816329481), new_root: PHash::from_values(2008543458613770845, 15392030768787735707, 6008831567759290061, 2440009288329156894), new_value: PHash::from_values(6634615370380034362, 12803711607699132955, 17535789197400019142, 3835046681391379171), index: 281474976710655, siblings: vec![PHash::from_values(11582426796021546938, 16513655243124075151, 16145236545580348643, 5964465885607580766)] }, "745071f40ab98c6d29b94a33b80a1cc7edb96066b1f667b8e1e45a0b46f171d3ce88ed52aee4c74b3377c8da9d502cb6869614b9e0214458095f186c822f83ca5dba9b46a2c7df1b9bc479096f7a9bd5cd2e728779a863531e59831f85a7dc213a41d91487e3125c1bd273c7deebafb1c61029cf5da35bf3e3b25f45a3d23835ffffffffffff000001000000ba7fd4fdcd0bbda08f6aad55f3492ce5e3b4f8d918670fe05e5493321f0ac652"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(9769232334983770814, 3092489619413231375, 10681365667084954511, 4915059472850801820), old_value: PHash::from_values(561186788516133140, 6031559805896008397, 9360788320446569700, 1403038720549908370), new_root: PHash::from_values(5945552316764830016, 12570085745245862222, 15697263716912532908, 6819643505880431889), new_value: PHash::from_values(5211810144231080669, 11078639078443102880, 2965899821311129482, 2147569505964539354), index: 72057594037927935, siblings: vec![PHash::from_values(564209767487982199, 12755261630081640539, 15215319465429104881, 5304897868591874324)] }, "beb2f78e0c4993870f67b594ecbaea2a8feba65e7bd53b949cd430a98ccc35441479252e69bcc907cda2f4d7af67b453e4dcd7c16133e88192ef7e604898781340b944ca54d882524eb994d962ea71aeac0d33d02ee2d7d9117dcdf6a23da45eddc2ab7bb6115448a0b25c718b3bbf998af7a4682cfe2829da3d7a5d16b3cd1dffffffffffffff0001000000774aed51cb79d4075ba82f4edfca03b1f1f8fc8870ac27d31441254381c89e49"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(2003335984006586682, 17598356596182754967, 17513912250140135456, 17450010664564867373), old_value: PHash::from_values(11211420498808039214, 13026995578085274397, 11930318529342334593, 2110953628438901600), new_root: PHash::from_values(13142477906999330873, 4610719542753973925, 9639817511179138635, 16801619499558320790), new_value: PHash::from_values(11632801944454396648, 4525794416714656657, 889907537278312439, 7023575581087128422), index: 18446744073709551615, siblings: vec![PHash::from_values(15558253421736615743, 5551270088965803050, 9805319473103679760, 9375125548248206216)] }, "3a61789c7647cd1b9726208a15ec39f42010f71866ea0df32dc12acc3ee42af22e67fc028bf7969b1d735b52752fc9b481e6b52e7e0191a560336c08249d4b1d39481d4b067663b6a556cdd8fe90fc3f4b366cd5f382c785963a7382ea572be9e87aad39bc0370a1912bb9160bdace3ef79f6ab23096590c665bce4bc7c07861ffffffffffffffff010000003fdf1d500e05ead72acc0ee9bb120a4d10b190271c7e1388880b06bc03231b82"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(15523235739570787946, 1546204001234278090, 18222843068495005860, 16772772116965087953), old_value: PHash::from_values(6794137988097401213, 13660346236835259933, 4574830742198125554, 7609636316379707971), new_root: PHash::from_values(10016147414663291639, 10105903097742017885, 14311831912045690271, 16682164412075886126), new_value: PHash::from_values(819525185533276495, 547213994301942379, 5566819550384008612, 6115353605507604515), index: 16305670784115438187, siblings: vec![
            PHash::from_values(13001083813255734876, 2639743614205061008, 16058459707929165988, 9874272659051734726),
            PHash::from_values(8941919341238466974, 8378817982379187664, 1806043756635537831, 16893194799798056139),
            PHash::from_values(2301191855225232398, 4312253771042383094, 536440234144913204, 6829161318758197779),
            PHash::from_values(6247808357958474490, 1419753587691723261, 6969509251044631201, 5869369275269156712),
            PHash::from_values(8165318522995294980, 15339833405345407966, 11135694873320108353, 9405982428864557836),
            PHash::from_values(14519566206858200580, 5020027762830185937, 1698422984428645012, 6814390276073636523),
            PHash::from_values(7451334286455484824, 12212516195773761795, 4410184332577783021, 10765657406177147107),
            PHash::from_values(4935996082940990501, 1600281301994985752, 5102354119155234982, 11609775342213163625),
            PHash::from_values(16104346148358090883, 10032431923253399626, 13138199463521076307, 9604106910624254848),
            PHash::from_values(16291866386100006763, 3793321191967871485, 17930485071265544006, 16578104508620903964),
            PHash::from_values(4148554869297958598, 15781984135882975292, 12049371465140824518, 2869833497605509058),
            PHash::from_values(1792411096777426517, 10288791641039895153, 171563183353175442, 8617564180127249901)
        ] }, "6ad6c3d5a89c6dd7ca56dbd358387515a48855d7388be4fcd1da47da5fdbc4e87d6188d780a0495e1de668db864c93bdf283415052107d3f437ab983e9db9a69f7e2f37c0181008b5dc56ef352613f8c9f3d95f24bd79dc62e46729a25f482e74f713270d0895f0b6b6a7d823a189807a4ad5605e350414d23602f24b419de546b72aadf2f6149e20c0000005c663070d8206db49067ccc6d440a224a4800ae3051cdbdec66621d2aa7608899eb9b6b84314187cd0dd5de58f8a4774a7c112533a5b1019cb74709b2aaf70ea0edcb8d2cc79ef1ff6e4511cf533d83b34576fff8cd1710713aa6b76090ec65efadad46899acb456fd99f3a65dfab313a16250dfbcabb860688f02344230745104430d59ef095171dea3484f3509e2d4413162e37cef899a0cb3091c2fc3888204868c8489dc7fc9d195172ea7b8aa45946a3aa9b4029217abc23e16da93915e9831defe0d75686703c9cc7ec6927ba9edbc4ac9481f343de3f8bd3c5f4c679525d46a10492e804418591c925d573516a6b87fb60934cf46696ab49a29351ea18370d0587f217edf4ad0ce1aae5b3a8b53c4668bcd4254b6800ba2b859a448856b2f9eff285618e2fdd134b68695a43446373a2b2ce1d5f81c96a64d374211e6c6ceb873aca092393ca8277ef4de04dbc66972da81f737a7c20f4b6d5cb2d3275506e35a65ecdf1871fa30347c21c98e921d4d68ce836102ed759dc9f6bc9777"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(8872950407145681546, 12700967531397275907, 7442680814467846949, 13625631503146880842), old_value: PHash::from_values(17230223897170768336, 12726504546565992945, 16944405700285075612, 10190693613955493625), new_root: PHash::from_values(17708139917076707775, 17905297408676062592, 9589935174322753246, 11673863689559418319), new_value: PHash::from_values(12915438261261885578, 4527330312034600059, 10299529774665156276, 12418739574407147337), index: 5902806900527071292, siblings: vec![
            PHash::from_values(17255782545748675995, 12765793774070590416, 10279821165711934165, 13198712026627475504),
            PHash::from_values(13840664132550115218, 1005816690308555604, 15401644920670191485, 6919752961556668842),
            PHash::from_values(10302394357301442370, 9763568578600543771, 13663940588844388952, 10411846933027851085),
            PHash::from_values(6234742914766523264, 12832239015856711178, 13389331599415929678, 6107616674743113952),
            PHash::from_values(11149147188931439767, 2991664361232196547, 910572569055288480, 17215322803854778981),
            PHash::from_values(13634719679003469950, 4624044959019773752, 14964177727633910806, 6100517061605498306),
            PHash::from_values(15431533893464562359, 8970443362813492786, 14284456354664323313, 6851429925646245164),
            PHash::from_values(17056248702332340974, 4881644562959719203, 3428280504150366062, 13620420668034101378),
            PHash::from_values(6435052449274926238, 6828326154394596686, 17430096843814399628, 3470589700292337073),
            PHash::from_values(15263760007922538310, 12640366945124839322, 3239714966127695780, 13512198805065699266),
            PHash::from_values(17911488598615439777, 6356312362030540253, 11979552349991886461, 10607593663683562278),
            PHash::from_values(14367693659287567259, 10479473200685094791, 10254841380649665456, 8076894481450758621),
            PHash::from_values(850561044204287453, 8261792250616613993, 6725555449176861370, 10948202034261463791),
            PHash::from_values(17595108294322274062, 8996228170891109902, 9153278836016538534, 17839512853634849004),
            PHash::from_values(7702964110847040347, 8263426745212512904, 3833056377875140095, 2805850340610884157),
            PHash::from_values(2304846390366331930, 13774298709485051223, 17075662864348822047, 17155210867910302894),
            PHash::from_values(7978454608329897662, 4404735494387854176, 4559526137431176996, 9765624547467595588),
            PHash::from_values(465704366811535273, 10939081212568017254, 2003229826685761035, 13668142407299475763),
            PHash::from_values(7387801582264276274, 16743173041533144364, 11480997011167243548, 6140925388057239703),
            PHash::from_values(8780511703853871880, 18064968262741529349, 16927884876956982986, 4274379550112094084),
            PHash::from_values(2544886634442696627, 5715551661659349672, 13564773632401210897, 1425464349222991193),
            PHash::from_values(10296639596754793316, 1578118280685520917, 18392739664998580040, 1760365490679493693),
            PHash::from_values(7456080229327934756, 17962187426483882175, 17135833965168829443, 8573583325928500309),
            PHash::from_values(15960399671374331994, 109529083974376630, 17285981560757676353, 14815549020619021953),
            PHash::from_values(13720209310476492984, 15793964484487711793, 2796730105148967772, 17580447612492204187),
            PHash::from_values(14089133605450147179, 4437076320379322723, 12087069888715646471, 11046318270164366104),
            PHash::from_values(2415646233668923113, 10436360059520633045, 6814452844418274797, 15056316011709204612),
            PHash::from_values(492703219104942862, 9082347581649005931, 5919041274349207105, 680694284613838646),
            PHash::from_values(7499423368441855072, 14326301619964369221, 4762318639650274409, 16962450772971799441),
            PHash::from_values(16656245758259095918, 5884423600659698794, 13269272077555358561, 18254899835019431569),
            PHash::from_values(15569819910441965657, 6388901414714946748, 5912327388964434201, 1958185521329095043),
            PHash::from_values(5294017289323155049, 8614303039637383776, 12705342792709565297, 4467880233385475124),
            PHash::from_values(14707613814829839762, 16633525497495872429, 6527669991107659774, 1150794207036942591),
            PHash::from_values(17050411099541892086, 600961089597452377, 16060150497559233321, 10470155712267340286),
            PHash::from_values(9534261370726359478, 747062153375797442, 3652090707450025128, 4878643674459925897),
            PHash::from_values(10963909081616599113, 5570453844128633993, 13275558120683398023, 13001560604256787283),
            PHash::from_values(4084398318738673668, 16828473041779780574, 9860560800672905010, 2020550480481610921),
            PHash::from_values(12663448814989942695, 8843108181186573350, 17598524869119364971, 7681752685313511824),
            PHash::from_values(8251974693919145545, 1538482515548530050, 4244809937006724283, 16705668606743821201),
            PHash::from_values(5460505182332200666, 7505490402302589811, 16377981266394071641, 13172742067968403862),
            PHash::from_values(1115238702263297097, 15500927250067937283, 15502011143607391371, 6452566322713118752),
            PHash::from_values(7984390596416126137, 7151733112025193657, 2744485130705846608, 18043957799029012563),
            PHash::from_values(10465217227731990316, 8167729304947414760, 9772130223176219075, 11416135214362611690),
            PHash::from_values(8713268138978862844, 1132852501591093465, 15091226299317309645, 12301619823005288944),
            PHash::from_values(13334536005615451681, 16418761636927636593, 13634645411915243414, 11977193150875274111),
            PHash::from_values(6320241780537443499, 15313152863361490363, 17142552488523143182, 13579893059107453973),
            PHash::from_values(9305126433887724397, 8317772902579846263, 12948218466408977181, 1037352079563410296),
            PHash::from_values(13577050440320323375, 8723061141466021492, 1878045986732942974, 8285108659242425257),
            PHash::from_values(9642350671838054419, 2884189467296232510, 18120093324931263525, 712775494618451132),
            PHash::from_values(12550531921819797534, 18379252451981327424, 383878024700478648, 14745688288048129313),
            PHash::from_values(18025277263129533574, 14599756152982169878, 9989704377913380986, 11838565623908619782),
            PHash::from_values(16768230726576012185, 16066231535556729770, 4600651869290328606, 12736664978354212676),
            PHash::from_values(14804874636777249495, 16287873999941453833, 18327738500289047445, 8059536376152264293),
            PHash::from_values(14350292601739730840, 2842050845222814083, 190469979619145316, 14355341308951189817),
            PHash::from_values(3066501337127308334, 16263358931841913497, 7545519201063067642, 15398762281511075202),
            PHash::from_values(6679570366816598288, 637517082403417756, 952651338137255457, 17361554113188436667),
            PHash::from_values(16538848730444306675, 184096932126957749, 17786754102383097348, 4145872640495278881),
            PHash::from_values(15702573865637942927, 13225998057667910821, 17689453628414137401, 3208100106801828976),
            PHash::from_values(1862984244306615608, 18336402125347370066, 790216576988234513, 2062441523150418777)
        ] }, "8a729367620d237b0361b45cade642b02593f88ac4b649674a0f7111a9f717bdd0714f47580d1eeff1b1750a75a09db09c909887359f26ebf9aea86ad99d6c8dbfb945ce6ef3bff580e5db7920657cf8de0e883c3b4b1685cf2585c42ce501a28ae00071abda3cb37b44ae95ee4ed43eb4c679c4c247ef8e49af9f7ad83958ac3c00a4039afbea513b0000009b4dbce0ccda78efd0eb5e2bcd3529b1d542cda8e242a98e3088ce8fa83e2bb792bf2394b2ea13c054230067f360f50d7dff3e3574a2bdd5aae10af7a7e6076042f7f0621575f98e1ba6a683e4297f8758921c269211a0bd4d8bdd0a9f4f7e9080cb8adca54186560a260c95654515b24e6b19632676d0b9e0d85092019dc25497accd304cbab99ac3e370d2e2868429a05cc158ed00a30c65227221e11ce9ee7ea807e74e4138bd382fcf1764e82b40166c6e135c70abcfc29d3413f263a954b71a5bfb50d227d6323e4206b66a7d7cf198564d5f953cc62c1da089372b155fee8a3cafd3f7b3ec235beeaedd15bf436e974768f4b2932f82b08ff96e7405bd9e140ab61be64d594ef5329b7516c35e8cee3618bb24e4f1b1dd0dc7f1022a3046570939dbc4d3d39a6fc1dac39a6bafa4d78ed198c7f52cc20f66f638f984bba1b9ee36fb6392f8dd2541846a2836587d5e765564eb3fa6260b8b553cbe35939bbb7783424d64c787970f785a916e91b0839939e783508edd712fd7bce41670ddf59463c3cccd0b690c147247c8a772ba2a61290cf9555def125d7dbed3ef970ebf9b53c5612ef40ea6537cdb05d97ca6e3ddee9afa067fec98eb2e6cae92f75bdb9ef80b6de66a88aadadfd796ad72ff0d4b9f77c031353d4205cd0462f0261a64a0979475fc1f575dfa68b22328bf1f3ad785e7f0f8ecaedcb664648d13eebef614d2312ab96e60eb8a4898c3203d24b7b155ddb0463f440fa411c9778687a957267aa7837606661944b4676ccf970b7612efe9e6cc1b33a9893e1affaebd3255ee9565be86662ccd7a112cb35be81cedf1e5f3b1549f976054bb1af3385508b35e9edfa4da7905136a33eca8b3faca5eba999bedebea8417a0df8da5513bb3a7981fe9405123a8629938f4b7514f11fedbd9bfc13fbc59756bef4544c8136473cac82803e58e1588cf0d379ae615483f7ac2462340ff3db4ce4216136e182495e7ed76517967bf488ff04b8246f90324f6a733b6ceed552c2e329c7cfb765a408775f0ba7eddb6dcdd1e1f20850141e9e9faa424e4ef811e628e56679bcdb860f5d2acf967be318c06c5046f2fdb5c8b0b8236fbcf269b48f656f54bfaf36be5dfe15da886c363c1819d67a9933d0766371406e6bda718f30dd9f0674c99e9aed86c73198621d548cd0f2e66d590ed9533eac1cc915e8408f40fa4c7f2d00e0b71a2f76ed6066b2dd15201fb0a7e41be75b8ada8245236e70b6bd84f7209607c3de8d14d13684559145b6b3fd1c6697c93279227174291c3086b1bbb66eb6ee9a3c044df26e76a143f7916aca951615bb2a2a6ec25b8918eab6cae6e56fd5998b252b71c13d8bc3413a1fcefa95819b109776fce0c52834122535bdf2c1b690ee2fcac207849606a2759f9268c7771eb0545f47152b0343cee816619013e92758f1ed7f01bccade3a4d04f27d6e6fe07f39645f1965affa803f03b71f80ff66b92de8e3a9fec59b0494ded0a570829c35486c91de1defec9b8a425774d91b6a1dfb533805084c2501a0512195e0aa854101926d5ae3289ede3e1926cb44349c86f6f38a127988914fff8413a4e4d87e3621ac6413cb8535b70fe7bd26eb404109f7da1b2ae38de6b850712bf8ae932f73f02cebfd788a9ecd9e7f46f0a1ca71fd1789a9bbdaf26f4f9b90908b97a6bcfbca220853af490d1831c5e119b6a493e906643e7847282656b58b2c95915bb8455d22598e83a913b5c601675d6e7da261747889cc74b737b594ec1db286859c26b0130474ae396e9195f1efbceb649e42be0b01f7a0f03d878dd345b1ed78b94dd7e003522d720c8f622e21e8c59b93c5abff140ce6eb91ca9b65f0f40635041107baf5e162653784369040469fa2c77431c9feb3b91e856f042879a5971c3f946bba9949d87ea4fe9ff7d426e9efc66902035bfeb78d9f03f1c59b3b80fcd50d7cb5cce6ed1f04922600d22b8aa217e5d03d9c90db97104e2ecb728dbe3961f9e3fc3fd37bd7f8b297cb68937a6ab4484cf6902b657bbddea8b653f83d40e18e9c5a994e6ed157ce4b3c97875bc6da3f9e130732281773ca4ac62aa6e731dd375b41750b1b378cb6361386a650e2f8fdaf0705f6bbc747e1833e4890e797ea610e7df28101aa95ba8df6d9efa721308a842d982d0853e741d170ab30628256c74e9df8077fbbc0c56318949e4091e08458e49722cae40fc9245ba3810ffb8c4599307cf53052125bf395f35a3cc86dcc2362ba626fa1669d349dec09cca7a10b138348fa28a06563927b6084ba4997b5a0101b9b4e8aa9b098475b8f6de1e7249f47fccd83f440ff6e950b9c1b0d75a4ce50a7b75cd09c8d4281b270ae295abfabd0f3559fe650ee502a239d96f98df9c15177b26c783c11a972ffe7027643693f36fafa40239d986d5dc6a38c72eccbb16b8668e2a99121d13c80eb3e1fadf4049bc11b76882bd267ab564b3d5103954d6db99b25c9c2ee6a268ead80821be783c587f380dbb9a51017ba1f0f0f3980d344bcb85e5b5a0aa332f0b8e020436c42b9e3ed7f6215bbb64331989398f96ae28bcbfead9a55c4dbb282f8cb739945e305a907df570d4d0c50c76852c389d0bb84ca6da1952340c2495fc77fe1143023fca69f70a59736555a3439f1c"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(10814825257160851657, 4309240750749776239, 9298902922720305531, 4250480833581135747), old_value: PHash::from_values(17494534680550959061, 4937573700308599727, 1286332280138584066, 12275803232364732708), new_root: PHash::from_values(8627396981639442996, 4103831249923305997, 12204918462097918476, 9050144237227705838), new_value: PHash::from_values(1272594493624380042, 16642772406859216347, 217443645538397909, 2445991814712054520), index: 2547784226815666723, siblings: vec![
            PHash::from_values(16822226396772772442, 17522269342786985920, 10844587198020879771, 17358171447112002145),
            PHash::from_values(14389966754387048455, 3869770047100380140, 18206781592851955583, 16235869060694299206),
            PHash::from_values(17841841016555021147, 1390045505207752915, 14970043375290913693, 4169186577402551324),
            PHash::from_values(16216596738140725129, 18333913258681862840, 3449360263538810240, 14349639425197029027),
            PHash::from_values(6615466267093471616, 16731706359477018726, 14959359079396108006, 13746963278430836528),
            PHash::from_values(17979885850009010817, 7062069214985923356, 16317643679477668027, 10538472451975091680),
            PHash::from_values(3670283303563860406, 7560728241707461092, 7706707314413883591, 5045893949477767134),
            PHash::from_values(16942068782678158721, 1872344655614673801, 1502834131618782791, 12095529624148120640),
            PHash::from_values(129410204830762321, 12949928750424905579, 17164622688068871123, 17756627024842062726),
            PHash::from_values(787677556370681529, 8715873418838844339, 10811975636355742058, 12731075231954394733),
            PHash::from_values(13685110894352640456, 16348815497685936267, 14832962595705082869, 41318404280369889),
            PHash::from_values(1852361290468261846, 10853016776549638289, 1178338982402859287, 9076277261069441301),
            PHash::from_values(8369864603991155654, 15751676704648847007, 7748712804923123741, 15194190631244238192),
            PHash::from_values(9808218529682697999, 1227017569921373717, 13785782610190900374, 1522055248132198699),
            PHash::from_values(15900155700314281090, 13214920839148872152, 10482638240186980840, 18275971988176822930),
            PHash::from_values(5211847102499299738, 16113756697159615032, 16151287614495647384, 15458600063122940490),
            PHash::from_values(2135841204159534583, 12638002462799231711, 13418791517467455697, 8307481218273192346),
            PHash::from_values(3253463644494990839, 5032893816686656539, 8174381823041117771, 2666756497939227890),
            PHash::from_values(1781681530105466558, 8784062972610308245, 17882875675640155924, 7606973492517957637),
            PHash::from_values(1276385836093602872, 905146801306756624, 12567750048539956748, 11052371339714751668),
            PHash::from_values(2273561351463777654, 16378108909913663782, 18326332348979569122, 11089953940853725528),
            PHash::from_values(9100412081176980108, 5388878026667644761, 7918225934403217893, 2866625869850619911),
            PHash::from_values(6907645619902326754, 11516686381939187646, 2250693734563812562, 8722005806026132390),
            PHash::from_values(2288085608927584676, 3555070611593213202, 8536204496121660591, 18011713827396476289),
            PHash::from_values(2160006277821505732, 7189773417892220309, 3964715565895034614, 2671966123020037366),
            PHash::from_values(17511181649911988926, 17015486895784931880, 15608032834568760119, 10213744701791760710),
            PHash::from_values(803924549697413580, 14352845278904811049, 17195162816634636601, 10203073968169844333),
            PHash::from_values(2316320662617936662, 14046325283326694790, 11930507917308848143, 6128541991377546202),
            PHash::from_values(15233664578611725256, 2947097983643672551, 8362696344219242790, 17786832685125662379),
            PHash::from_values(15247580449898113301, 2802193017175812867, 10093454947605289592, 5039449110086886114),
            PHash::from_values(13884056715632991165, 11243891390656149110, 4048029667022699440, 10298954476521450883),
            PHash::from_values(17837466070922692580, 10219763886091011999, 42090871076414275, 15744585967151211742),
            PHash::from_values(8666351071717078935, 299455915184214799, 8953644111502644352, 2910998733772346173),
            PHash::from_values(18390588222016167771, 10107343143734920391, 1973804821782604394, 8899069332136649749),
            PHash::from_values(672753174439212623, 14973455826432576320, 18268504776777514877, 14854678134611590845),
            PHash::from_values(4526587485824652941, 11913925339333931807, 14780281097825017783, 5602888823401634016),
            PHash::from_values(13066937501999486769, 8424333714368938182, 3115861273463212496, 8279446837582225728),
            PHash::from_values(2515400027604968117, 12065787518011234377, 2848825592306171006, 9163583762068746257),
            PHash::from_values(3579495838421147504, 8888527923327416823, 11327589479670364227, 4853182336877676824),
            PHash::from_values(1346940451498969993, 4175226948987831924, 6019635440901249239, 4477114743335923482),
            PHash::from_values(13312391392565446583, 8053670263266039327, 3617647144408638036, 4804987523152656330),
            PHash::from_values(101478891268556023, 11828793880536332226, 11334644080338179035, 14933889025240045012),
            PHash::from_values(12630655675194133004, 3218559671996636025, 13719358511369513220, 14754029113205764576),
            PHash::from_values(13309743196241671352, 3015132298615246305, 2950699342490365928, 15943291992096671887),
            PHash::from_values(5761192253947745454, 152390897692026478, 12733045707708423590, 9893457349897268985),
            PHash::from_values(161100330492192779, 9118505627751869909, 7768962129400145850, 9530437848417871947),
            PHash::from_values(643885190883491094, 5490993604793859043, 10275088774205803847, 783111713951205119),
            PHash::from_values(15539201784582877481, 13723492312310007573, 3025977819437687007, 3403565036282572005),
            PHash::from_values(10185442083321536190, 14202416578971870636, 3969004827852607479, 16419849404245557934),
            PHash::from_values(2419251308009519348, 7490551841397385399, 17258741138526838537, 15557236749697960029),
            PHash::from_values(2005031635673452776, 2590840356642955595, 4019510361316605879, 2657948063918162030),
            PHash::from_values(1077503980136299721, 18113574428122141417, 5860030877327034651, 13950559411441948302),
            PHash::from_values(9486678548902951115, 6637523949898008695, 1441548399936800500, 12319157755537853752),
            PHash::from_values(17270870552193443786, 3421504854162757925, 3987777776745402763, 13079699022299293314),
            PHash::from_values(4881716848751302223, 1282769374787784672, 18344379572197889781, 15917748037292552726),
            PHash::from_values(3958665488600228504, 7178055576698967541, 12814121357068275091, 12789071144208082364),
            PHash::from_values(7180202419388648583, 590202914193799808, 549149749231755953, 4234119404727880252),
            PHash::from_values(11257601304311430251, 1561740323271355601, 2701794148092776036, 6811058693061729530),
            PHash::from_values(16722411651387748804, 11863838458506602512, 15313212949842391817, 324882705959793703),
            PHash::from_values(9119207974100895762, 6933752430672143923, 6793400197790614685, 7281282449572863837),
            PHash::from_values(8430291243124640313, 7096904920917645826, 13103037022974712448, 15760433094126815524),
            PHash::from_values(4713604897694817028, 14037653934217555604, 5270512809415204451, 5692860847976448250),
            PHash::from_values(14631229968633830239, 11839963828048731274, 15490114474264818794, 11790576062744925441)
        ] }, "c9c0fea045fa15966ff913a8a17fcd3b7be195c5f0560c8183b73552ccbdfc3ad5e7fd189a12c9f2af8334bb1ec985440250c7bc64f8d9112421b1f5ff695caa3472e54ad8abba770d72d35dc7bcf3380c0af445ad9460a9ee8501ea3b92987d8a6a990ff329a911db3584ac5301f7e6d56efbf2d7830403f8d26c9798e8f12123eab06b418c5b233f0000005a2ad7a6c78d74e9c01f895b219b2bf39b85c87999b67f96616a70aff69ce4f007b8eb94856eb3c7ec63dddb5a2fb4357fbf0f21657babfc465270aee36451e15ba3c1dadff39af7d35889af056f4a139d9367982247c0cf1cdc67541aeddb3989dfa26ad0ec0ce1b88a8eb6f8246ffe801d945ae296de2fa336cf91072924c78091af0985dbce5b66a0c51a49f632e8e666eb1ad3519acf309735674406c7be8102dc47eb6285f91c2b75da88820162bb18aace78ea73e2e015371fdc2c4092b699f8f53777ef32e4a93c02471aed68c7508b7778b9f36ade47ea10d09d0646812dc47fcb511eeb8983034f8be7fb19475e782bae23db14401490b91bf4dba751853f49e5c1cb016bd7b13b9663b7b3d3a3f48964fd34ee86fbcf5033366cf6b9ae05719064ee0ab3a3281db200f5786a7929958eda0b966d5e6aa978ddadb0c8a9b701da47ebbd8ba8f84d13a9e2e2f553a873e444d9cde142d1a9deca9200d67f0b8ac7e8b41991a098ab41a99d9617211eb70f4d5a1015d9ffac146af57dc623020b83bb27749fde63c5813299da1da8f6db3df5886b708de178e09bdcd20f2f245dc9ca1d8815965394fa3d0711969c2f673ef050bf2b5170192f6d1f158294a2e65db3a8dcd82160d07cd464b7e85945a7f0cf799192e24468b14ba1fd9aa11e80533354483842457b57909fdf98e62d1f83e624e04a2246afdafa87d6f755924e4208a41ddffaa8e9473463afd130ac11ca1f39ba9a296731271a4a73f78dc573f29f262d1b3cdec7426ed8454b9ec654f53c7171f2e421e2e7380225be8ecf70e9cdb918956819cfbb42e779144f01f1adbc2cf8057058851666916938fcb2c427a2b6111066785938ba8f0c0c561f15159e69aeb4ec67ed2ce9619976350ed900508d1f2669105447bb4ae3e261ada02c3654fe589907245a6ee7998c2a3a6092284b7e59d76e850324c94ae5a963e78830e36d073064640a4dc827e2a78fd017e3dc5fbe5f10113f7dd39fd294dfe206123c1fa60b15c511ca0a79a4e1cf0fbde9c01f12b571bbe2255631af846c31c3b07676815df5bd4b76f6f9c4202af643e2f91d950d039dd434c763f6a6a21ccd7f0537f6ac7c3e08bb1425bec257b0ee3604f3283293072e2723ec37ab1a0b2bdf9ad84671d308b182be8dcc21ee5a1e1d280b297e438dbc8c2fc7394983547a7da1ee6d7ecc41b799988d16533dc95e392520869546b06c92eec20fe82d81bdad91a5daab1f8378f40c55c8439a0b39d968d3e7df59710032e6282651a58104440e74abf638a41686d7f615295e50a2499ad3032bd8d4b363e326781a6c24cc27138ce22263f643b8ef45bd5baea00514aec076f621a9a5530a9cb07b21e7887d2d3883edfaba873ced8ee4076e72e2688bf79f07d2961be5d38d43e3cb9a6c899500dee4a5cb840180da97b78528621045780fd3717a91e1270480146287e1bb417c3dd31cdcecf165285b9fc1e78c7e38ffc7c44cc9097f448c6a2a4e1a075d641b15e4938568d87f7b4f36f79f72195609404b84cabd66cccf7dbf59c54dc486fdbd3e495a0f6b26ce8d964ee155abd13e1f338633f9c356a5b7df4764591b1ecde058dc12b375c14d31d7e82c6d1657b5c6c04e12e13ee974d0c92bd651c33d2b40e1d14a0881e672b5e26679ff7ee82249d86602d24972a77e7c7350c80f89271130a57fe1962b7f70df140480ecac31f73912860d655a7b433834999dae339d1849cb439ff75943894b3349344bb11274c60eefc962f139d75845448a0a8a531aaf336723e8213eb7c7d480701dbfb81f56192c6f62c46f54e22e25e9763432cab7b2c3b1beae42f744439283866801c2b7aeda5c5128a4db930ad0bcbe4c9dd4958900f2d43fcf0cca37a06a1a49af79dbc111f89eaa2c046969b8e0f364bee0b166ea4ed7c0ccb834a83febb4b5b8e1cdc4c9d9e6d729e8ef1d246bfdf2288f88407b98f341ddae9449b3d4ddf34f6ea6efcbb6661d02a6ddc5cc9bddb4b0f9ae1abd0a9f4c890b682fa4e5573c02d5ed8c788e708b7ebaa75b1ce5e5d06b4ba8e28cbaea428416bdbe6e2b8aef08e3fbad4d97ed334c470d24e6cc72988eff468269f42bde0a29b12d5fb155a6d715c70a418ca373bedf60cb61cb6efe29e5ec8f1d5ee43b2fbedeb1289cf5598daca5bc85a11e19c5f70ff7bbdcbc1437ae42777d0906dfe3f4784e343fe89221b7a8238e36c9f367091f50f09f5d83ef5d4866e86568e6d7e890bc47a64dd31b4b2173d79383f423b73f4799602bc8376e804785aeede224c9fc173c2910f40ee9d2d1f8f85760fb1b09e6ff080353518ed6fa18df579ac1cbb8adade073a7837788d185dd381d5cf406c4d0a1680114380dd57eb570f6aacaa73e214375aeef2559a57589a07b2f8b511b82c26e573782662c29f66c84b54f56dc079c57bf43e0cff930f34fcd11f596c939075494fe1672fe0a8133e7dc98629db84901f036f555271b84939d63930dcd6c7be7d4b1bca5b83d72e87bb1878c0fdf0e34a56380faeb656cd23008b1227493c9f89e073cca644f2a9dc23a6bfc74aebd083b9cd12cfeaf8c6aac15648e4c8576b37e25fadc4778cbbd855ec4f1d13cccf011e81068e77f38d2a4a4097344850b7683d427b4668a193782041288313956ef8d7e33e6b65e19a339609dc460a67c01475e5d9f135ccf4f0c6539ca87533869fe74029a04b06c457d62801a33e1bf56d7b52449bd91654eb8da041ba442ae166a4194eee6e4e0c3cfc263de56cd799f2449fa805d77c71a014f5f1b780b23920ccb8a9c51ec5e0050a46af4b0500bf1f7d6019522bd758aa0a3"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(3524630124170570259, 11258176534381178576, 2562959023041350268, 3438075650495232940), old_value: PHash::from_values(10202398031313920156, 12038414956426927179, 8894082867583609415, 16046455947247038424), new_root: PHash::from_values(8218680496973002996, 14567060137786395960, 7643052806538571536, 17316535523385021492), new_value: PHash::from_values(4540823411019998585, 6849993295697616691, 8038826887348864944, 11177655863907559974), index: 10970611105109735452, siblings: vec![PHash::from_values(9217396032926892934, 9777082766634155902, 7614607472525639024, 12646908832195373576)] }, "13ead3736c00ea30d0ae6ddee8133d9c7c0a43fea6759123ac3bb0a2967fb62f9c609c71f432968d4b9c93e09e0a11a7476a35c53e216e7bd82f9d8faa76b0def4b881185e9e0e7238cd8206049828ca10af486d0894116a3414ccc34fb150f079e59f81d53e043f331fdd0f9c10105fb0c7496776a68f6f26aac555c9021f9b1c7805e1ac703f980100000086c3b328dbc4ea7f7e7fd29cf92caf8770fdecff2685ac69086ac1a193d882af"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(2158566965667827375, 5230178616640932984, 352724264514836398, 11087253445192870823), old_value: PHash::from_values(7383469042786127487, 1815522633695141299, 5824993799825042559, 120827880880242496), new_root: PHash::from_values(6665474508845318615, 7384653034521787010, 528900930878405887, 8695698027888879476), new_value: PHash::from_values(5451094021831900362, 17767505052938293869, 13670798840808707407, 3139614039313715041), index: 16417661412902142942, siblings: vec![
            PHash::from_values(10708463239438542270, 11178415451591773421, 10849816300906860636, 6385669071857177678),
            PHash::from_values(3000342413140479751, 2063658409644155309, 9249255371260076433, 16822155241788177501),
            PHash::from_values(17767572811350313467, 11145423926866545127, 8087803788749440831, 16840469150781332442),
            PHash::from_values(4569621949506150383, 4464285092204974249, 8969169303199127399, 10130568267905726736),
            PHash::from_values(16319880372040433144, 8499209647905160556, 3095538640032412062, 10522387968895369217),
            PHash::from_values(9189038375763743239, 8770602995178365997, 2086910228625118484, 12626188344239756582),
            PHash::from_values(16723253721384596612, 4903051938425750759, 5794612545143023913, 15940445410492274307),
            PHash::from_values(3612200040087465948, 11590638722719670080, 2117017732107599510, 3635134045077257914),
            PHash::from_values(8742313005501134157, 16882096695141240221, 3631042270949638908, 9738465026366534065),
            PHash::from_values(2318336004471824664, 5633463174689126056, 2653558079153383815, 17375401653519094220)
        ] }, "af0e86fc37c5f41d780cbabcbd539548ae57118ad920e504a76b72ff43d6dd997f4e5ca1f9597766b39d145f370832197fac6cb1ff88d650407fd4465144ad01d7812527c085805c827a2e30cf8e7b66ff7c612a9808570774a761da4853ad78cabc8bb8212da64b6d525899b5db92f64f95395e1d6fb8bd618f1f995526922bde83ab0e1240d7e30a000000be251095941a9c94ed8cdd9fa0b5219b5cd0cbdd704a92964ed43e2930749e5807cfc63b875ba329ad6196cc6396a31c91a1d468c1f45b805d7c4297104d74e9fb896cd5551993f6e70905b00280ac9a3f0778e1b1a63d70dadb3ecf775db5e9ef5f24c2f38e6a3fa910f378a353f43d679785e7f5e3787c10795d652a02978cf8fd5660bbdc7be26cbdf5de2442f3759eb1a003fe8ff52a0140da921b0807920792d496b705867f2d649599f470b779145554c7cb31f61c26959615673b39af84b4dbefa7ee14e8e74428b1c2230b4429a9459c68996a5083d6e50da5d637dddcaf1057cc1c213240df972b8238daa096fe79316928611dba3ec27b279772324d352c185cef52799d8db0c17f4149eafc826114b50d6432b171244a58fa258718a18a2050622c20a8f696f6e8142e4e8729ce8a0355d324cc91bdbbbed321f1"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(4276437206660845455, 15204714614487290046, 2061800159565762404, 12189069171405526348), old_value: PHash::from_values(6231102930439630247, 14491406362422963094, 13985279153190607882, 14448716904550549185), new_root: PHash::from_values(16067791664325715239, 12164687769872831081, 2031110367296309133, 14567549049470858911), new_value: PHash::from_values(7208323378889783151, 17407967765337723560, 7973470433853113245, 13795694457654940963), index: 17017811135702344711, siblings: vec![
            PHash::from_values(17255103727054687727, 865221059670633688, 4134512228303759001, 7699778874008855128),
            PHash::from_values(11808136489442997839, 18239163991732220029, 12055133994624615115, 9189902934247458525),
            PHash::from_values(16654152237586555989, 18030961476088923221, 14519899206645324339, 13273998035927567555),
            PHash::from_values(15352583219590139971, 8201075639937405025, 530870694897040703, 9404892954269772785),
            PHash::from_values(11307396499348674948, 437915972273408409, 2947272737206995797, 16724136874630302140),
            PHash::from_values(2634227999657027543, 17906882293834099389, 17296636411641700062, 17528184285060858072),
            PHash::from_values(18144964159099875927, 13365368646280334035, 12740426758150684753, 13099049273913999025),
            PHash::from_values(5783917245632522140, 7084137527630330343, 1879423998941763430, 11272934699679222174),
            PHash::from_values(5703081481455714083, 3068235875092122691, 12172376584554566283, 6288876861983694095),
            PHash::from_values(13760601381549278216, 14419325264106758275, 8288356930611424103, 17565503328753463327),
            PHash::from_values(16257052257849617005, 12099442785047548519, 2892406340303751721, 13883979758568882511),
            PHash::from_values(1063619537827506813, 12879967498890929632, 10250811033069937840, 12755152781195842406),
            PHash::from_values(8410840567019548360, 8379858199084226701, 16379553998736811368, 10982185140280091443),
            PHash::from_values(11235265305319778151, 12781557661239324910, 7279899791154511196, 2310487748807783755),
            PHash::from_values(8346683908728021986, 18237930173635509475, 9506923233902105237, 894538994892099227),
            PHash::from_values(8333366958968351745, 11754426165556783729, 16102945827966194786, 17168928491555030872),
            PHash::from_values(787552398748721873, 17847252904904332072, 10731484130597206217, 816387173514686640),
            PHash::from_values(14170063419690598720, 9629128258194972411, 612711564013307743, 10943970151721458523),
            PHash::from_values(2758836031601853046, 4917372645361967328, 12748508402401059979, 1220743305052691137),
            PHash::from_values(8506132247767061469, 10590569169924951588, 4732904632846600416, 15053930833793255496),
            PHash::from_values(11929690410126228822, 13167117691941195465, 17917398413712117594, 8169141738895626167),
            PHash::from_values(8369384966304840952, 11251654587803852570, 12416301257180359204, 15277608473968216646),
            PHash::from_values(6151420801819891081, 15507842236195363945, 11868482311821199900, 18191681311312241729),
            PHash::from_values(6378740718037170645, 17952368673287244540, 3257012390823169099, 10143477545146236981),
            PHash::from_values(10117848286550666011, 6231307077127333726, 8524697426851406282, 10744189464512279433),
            PHash::from_values(14616730737327320668, 1288443277982956918, 17042822188313817728, 12353198972489711339),
            PHash::from_values(12347812108913629589, 15691252494911863992, 4017748061722104623, 5735671471960513325),
            PHash::from_values(13770572750656430333, 6538624268942991607, 9269633248208008221, 14753421594219326552),
            PHash::from_values(16980321494920081019, 5235561701370462173, 863175872463585555, 4515483788760838351),
            PHash::from_values(13896556364043525631, 3836851466180113569, 17428348115641320679, 1275239307540982743)
        ] }, "8f8f485ffbf4583bbe90b44362ff01d364cfc23c52fc9c1c4c954ab8d44528a9a7edbff719537956966b0ed04ed11bc90a1c9aea4ab115c2c1c6eadb782784c827e51d4d6343fcde6912cf4e13a7d1a88d474f261ef42f1c9f36caa5ad542aca6f77def8eb1b0964a8d26782738695f19d03e5441d75a76e2315593a042774bf07a4394e10692bec1e000000ef0d9d156b7176efd8ecda39f8e1010c99e68d4ff7bc603958e25a3a171cdb6a4ff6933093eddea37d704be703871efdcb02564d7f704ca7ddc6234c0718897f55a49ffc386f1fe75584082deed73afa331a9212660b81c9c30cb290e2b636b843104bc418550fd5611094e6d712d0713fbd009715085e07f1ebd20950e4848284592cfe34f1eb9c9989d3b041ca1306558b6a6df0d0e628bcc95913e11118e8d7e7f1b068a88e24bdaab64e920682f8de9efdc42cff09f0d800a32cbd9e40f357b2573dc4dccffbd3caae95f8537bb951007486a216cfb0b17efbb2e92bc9b59ca72e24179a4450e7796b4a8ce94f626697445f2b0e151a9e098efe6182719c23bf4623646a254f43ccf9ad4590942a8b52a8fa02f8eca80f1db6a22f9446570884feba0c7af7be8320e64beebb1bc867abbdfcb62806731fb04a233634c5f36daa161ce5a69ce16712ec7e1bdbe9a7298ae4eb3de423284f4136aa07ceadc07daa5f9855bcc20ee065f80133d6beb2b0e4c9cd5232428e669303f3df6703b1c82ea5e3ee4eb9748d588f38a23c4b746865094a94dd4fe333e3f7ef328f68986727dba844aeeb9beeb0572af93661b15c7d341c4a6607654b7594b55d801020e2e333d8ca60d573e33cec3ddd241afd9592a4b74f60ef839b4e47f4790a6a0c012c49dc1811a67371aa91e8511c20a3629448d9e92779df588738897f4944eed1a26ce9bbf2ed0a2893614df52daef7c9f8fc7cf5e3ed94b0308714cf63540b40416a9f9a2da6c4fb1e632e2289a1855f87c9d2ebc980085bdbd58ddecae09776422df9c05a4926e0e0051b5e043e448ba432f5d8ccebb0c11a9a7391f3f010dd93a64036da0b76248e947e8c42f992e0489f04b0a7ae4148088c8d554eead0563df5c738c68ea5c98eea47c7ffbab65a4f7544ed62a7f8b7cfb02a219f5e71f83c18b1480726741a5f71d93be8259c24aa788235904fac468a5f7cf6f704d489556caca03c5e55695c398959ec36d71c0a1cdbc751b5a441e4e0dbc4d575fcd5f9ec14e3d68558fc0a235031a023f94b8c0f58833b332d35c097b915dfc48c1bab25f368d1698c5e678d92c50c7a56ca212ad924cf4d7689b3bf8f64071b955caeedaf290fd9ca76fd69b95578e111803297c87b4484eceb3ef8f203616fab95591009b13d5cabb8fc2e200287c2d92fd3f53f93e8c1372d5b8c9ad032994ffde08c04f5e61abff760182621dcbd5a1db4969d535aa480582c05e1c5aebecc7b2ea41c6f38a6ebdd7fd3d1a073a8481341e1f8e19dfa0bcff01ff29438aa3eff1d02d0627cdac0a1349a79143c3f35e744a69645eeddf1d76b98c9648fb211"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(8635599309883297384, 2358936808276519529, 15659911206408888662, 12092840666508121912), old_value: PHash::from_values(16892238634535667268, 11252730786391254561, 16471923837439793804, 12697695407353377596), new_root: PHash::from_values(4680735459665058862, 5193675223271012682, 6788284578220503967, 11780106474643988894), new_value: PHash::from_values(6542454142892864116, 1904580320556886252, 12940078891446183724, 6572950679513041536), index: 11420466972947735801, siblings: vec![
            PHash::from_values(4443187118464038033, 13985791254824916854, 3593408489060709507, 3839907526753981583),
            PHash::from_values(13848889179114073892, 9015709703461587358, 3265232708741642853, 14087383558369334277),
            PHash::from_values(8133676728509933380, 4363213741316577685, 10618616872999535042, 8228491719986454799),
            PHash::from_values(14436680988780899028, 9179478122967968578, 15969104383078052301, 7007799642658663858),
            PHash::from_values(12532071795807175518, 6561082942634205756, 5559609488004142635, 17822003533967748759)
        ] }, "68ce33a8d1cfd777696aea6887a0bc20562129c0452e53d938579dfc8366d2a744c6a0088a496dea21e6f3db07bb299c8c5ae349750798e43c33689db24637b02e1ce9d81950f5404af9d02919a413489f7318a7dbd4345e9e216fcd6c587ba37472692a6177cb5aec28feecb56d6e1a2c272e3a316594b3808a896ad1cf375bf964a12334a67d9e0500000091f4a3aa245fa93d76979ade0b8317c28334566bfb59de318f1485068d174a35246fd876552331c09ec9de40353c1e7d653a8841d96f502d0554484bb57080c34427b2f8e39fe070951947cac73f8d3cc2411b41c9e75c930f2109779f793172d4aaebd7de6459c842abf9c6b70e647fcd318016d4a79dddb26dc765a5b440615e43c788e6dceaad3c2296992ca60d5b2bd6608e5fb3274d976ee703ca7954f7"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(9377703271172689580, 12251758351254725528, 6041353435869135229, 8514270807475802380), old_value: PHash::from_values(336115358672768889, 3002860716551033093, 700201202751183180, 12843118697299740550), new_root: PHash::from_values(14666089468337622929, 13982019161259823103, 3559162913774124616, 12268420171086086721), new_value: PHash::from_values(1950203342344156217, 1576539670593602847, 11929637714900650040, 18313852084309539250), index: 4598521260293121155, siblings: vec![
            PHash::from_values(11183018992371885704, 16195312890476745001, 257727162098607001, 5144461054490814294),
            PHash::from_values(3566677499187202924, 16290917423181415031, 6794758105661802315, 8194700536909937848),
            PHash::from_values(3171315353748014204, 10651799500319427702, 1701524866733824476, 6533575194517822160),
            PHash::from_values(8059220030190396686, 2133245322818739548, 3338257565496640058, 9779354488614911206),
            PHash::from_values(1455098824890544783, 12686818697793092503, 4727378509733653569, 1648240417335656762),
            PHash::from_values(10597847820147722054, 12104665125778505434, 7582686688549637857, 2766233000948279650),
            PHash::from_values(15345699791095526975, 7714844014090202244, 16131431360566302674, 12701606475317708224),
            PHash::from_values(16325194981755455684, 8804095494372672582, 1596103510313431453, 11391866757999556704),
            PHash::from_values(9675366929069617037, 12231614402881008136, 6995405927977383745, 13081751814582578813),
            PHash::from_values(13961915845499655614, 6463098841366699521, 1026057546920772338, 7401258424601138948),
            PHash::from_values(9759390711606517130, 18225449548662365028, 14667948172689863621, 12571086311165130555),
            PHash::from_values(4110566221256002141, 903971165645604085, 4387382458187119464, 13620714560643327902),
            PHash::from_values(10624895041805508647, 10523591140895347356, 14424472363170699159, 331891209485929616),
            PHash::from_values(3887910623419605752, 12540079829747947204, 6513527358547027112, 11120507646597197863),
            PHash::from_values(17499184311186239868, 1105767822714596399, 2045233544232354835, 4695636844847513188),
            PHash::from_values(15822406587304733957, 17960114533166244306, 14596811771772407267, 10336273117006450989),
            PHash::from_values(1968928706511748151, 2814925783155998724, 17077326065548795263, 10456995446878917246),
            PHash::from_values(13682590317189574497, 17491970620522509777, 8013499461379136189, 2449459414780827972),
            PHash::from_values(17016291610432951069, 10496205519093858567, 778976745099108684, 16375012729942494321),
            PHash::from_values(9313632643701958652, 6753482650760601303, 9261335279040159292, 13326605670010861252),
            PHash::from_values(2027281478437870391, 12125630305835467848, 8236920762149991757, 4650797253720223847),
            PHash::from_values(2846959231787372009, 3911204644509309501, 6851281217264618719, 10556762096742571526),
            PHash::from_values(15685579911045714982, 13274280232182110739, 18307036852298464075, 7415187717756466516),
            PHash::from_values(907598859253801907, 17916703721775456343, 17254896710639888934, 9482190837950333216),
            PHash::from_values(1003406481683341533, 9605816368913342273, 16131144743676838242, 7937426367843690831),
            PHash::from_values(12719715893651881538, 11625510349488750813, 9767599657392174583, 6024460990065971426),
            PHash::from_values(4029090881948105552, 11591219310654970964, 4487524767766199592, 9749697539510421161),
            PHash::from_values(2398875712541829862, 8916517615404912696, 215769476353265215, 11461832735877588953),
            PHash::from_values(14929134097769413517, 12551366737168636853, 15762997916888285281, 13924709800086878504),
            PHash::from_values(12557095098820442452, 7600830488458684330, 13819529397007895454, 4955616067793330646),
            PHash::from_values(13618168030030163695, 11814995658214234492, 18368095229169398236, 8246368456289839807),
            PHash::from_values(14568899302451722452, 15396892734129235226, 2932159653130069585, 12082157274159422740),
            PHash::from_values(12781697911569594518, 1857878521532556659, 9659128295073723136, 5837251103203770660),
            PHash::from_values(15399064451418035684, 14706719259773112137, 16005740749405860627, 5332510412271657870),
            PHash::from_values(10380687089798607761, 11095726590323230848, 15644864742907224812, 15580854288987180487),
            PHash::from_values(4844675905287651324, 12693471877425988292, 8661281336658194854, 9476574957567836323),
            PHash::from_values(5851796397870217731, 2714024936814134367, 4812618276427500365, 8399249343438984476),
            PHash::from_values(3529042594820488357, 14244864824465954547, 13988094408163178758, 15387194562198287088),
            PHash::from_values(4923529390446329460, 8541838014078696223, 428724072784618746, 8852766864604706138),
            PHash::from_values(17600719324774072662, 17391437620373287439, 9513949820878841432, 6958015645733143649),
            PHash::from_values(1636737971289512952, 4110656580574022098, 155684126834555867, 9434194652765631662),
            PHash::from_values(6157746833987646057, 10938080608779013310, 7499684926223445741, 3554884654142478914),
            PHash::from_values(10474682331974231996, 17773367307030792866, 2665138757805565599, 5706387915145737724),
            PHash::from_values(14186026943132434535, 558617262707690893, 5739476245740301112, 12823260736294621103),
            PHash::from_values(589336499877387119, 15242704141651068499, 4216844571385465349, 10243443715729021600),
            PHash::from_values(3766650406578892930, 1986672917176080832, 8314129242184177181, 17374707283471171284),
            PHash::from_values(6771787429766107801, 14320597343734165453, 1603794501834614378, 8130658762143511773),
            PHash::from_values(17253322519567741997, 10769866737796534788, 3208039362395117152, 13073846704132474454),
            PHash::from_values(13342453640308152142, 8558694728375855895, 5034858411729946214, 3398492626487273811),
            PHash::from_values(4959738891955762203, 15544590199889944798, 4440729049727594937, 17445380628626715032),
            PHash::from_values(6631387438386630433, 10533524082120946122, 672868622638508876, 1063742180966042146),
            PHash::from_values(13873738594064426839, 13076660286962208542, 11518640057434639039, 17391080250435871096),
            PHash::from_values(8727591215132022837, 2223137063295618517, 16762392230985042913, 2620571047831359822),
            PHash::from_values(4028185484684024970, 182366751884284922, 12608415796070869698, 8469528411386464413),
            PHash::from_values(3245963045079279021, 5305123716461104303, 16757854457812321652, 665740802119821519),
            PHash::from_values(1649829603711345837, 7163311972377804719, 8041060311263183905, 15976051655647817747),
            PHash::from_values(871751149070487111, 2558942579270092544, 4438970058364013227, 1394833922712634049),
            PHash::from_values(378757373996766671, 8156015560741051549, 9169175732255175036, 3010545667763148919),
            PHash::from_values(18053765111669683144, 1682381194228910003, 16728545682109390271, 8116324927943709406)
        ] }, "ac4e449f704b248298a376d04efd06aa7dc19003f132d7530cd1125930c42876794f3e4d231faa0405d1ff6fe94dac294c1949b9489db7098687bad068ec3bb2918f5cccaa6a88cbffcf98e5581c0ac2483e4015d0af643141c2d20c252f42aa39f433749b83101b1f050b407afee0153888c1b74b968ea5b239519270df27fe8364dae3b83ad13f3b00000088e6c5fc8510329b29d12b77444fc1e09963db097da1930356a7c19112cc64476c8b6ed749627f317742f35915f714e24b87ad367fd44b5eb83c388fb86cb9717c84e40a83c6022c760c39bb35cbd293dcd929ead9079d17d0da89e605ecab5a0e2536faea19d86f5cdd5f9551cf9a1d3a0230a891df532ee67c831a183fb7878f72b0faab8c311497bbbd5363a210b0416c7d37b5059b413ac1bb43edb9df1646878d4f711e1393da3e1673cc68fca7e18e15525e1d3b6962297c1b42a263263ff608aea7e0f6d4842c657dc1a1106bd29726bd5a5bdedfc0051d16cb2b45b0c408866057be8ee24644b3be346e2e7a9d71fca4af7f261660f824af750a189e8dafc1aef5ce4586083246597e6cbfa941f7c0d4a0ac14617d2e041cf7b78bb5be95e7f27cb0c2c1019ee63b278ab159f2425213e7493d0e04d737d9528db6668a9d8d0d2552708764dbd24bcdcdedfcc5f3042126058fcb3bf7c541657875ae5d0aaf1333aa0b39f5848057fc8c8b0c68fb05b2191de33c9ee7222eba7f06bd2760a056bf3573939cd283e2624e0b9297973aaf30052ec890cc7bed4b1d9b04f8a264eb1ca2f435c4d62a3b2a5007aea8e4fb589fb2645a27f0701dc9fa539a7c3158976a97d9f22fecf5e4f979580f13c4ae861221621c643e5ff3d4402a41056d19e0f57a94dbd261b4da02253ff9e30dbc1df84a92ca2dd196d0a2d1718f37bcb30b3a0a531b04001aee15a010277f1d8eba93d9feec7e521895f4b51e9161af48676653e2bdd135d0599af6bff2bd9a49834dab356f4459bf255c3afe211dd35042100326ec078115ef4e03aa914c21ecf3387bcf0a71ccb8c051bb3fe3fc6756308bab4081d75e597bb030b95d3c5efb1c5edf8680c436b4de3f9df1b8379b047ec359221c48c408d184e446a84d75fdc6ca6b4f7267305b1676f38a40e98db464566e82273ddad5d7e6634736df0c5dabf7a3145f061ea6e2312781922614e2c5d25faed9135a34808ab737b84b3b3cb705a90ffe54b5b623f109e866b3635f945a70980c576058b21beba4f8262abf5123b575ef20417e0c54829783dd600ffae0d0ec0d415fb6fe17b74e856281448bad56dddf4f69242e3a67276e42be029d368285b0dd80e779111c56a1f775162f237c8d87e29014fc592f9b53503b4862cf34ea3754dc3cd58c48dca028bd781700e4463ea9c6048e41e24d87e62a5e32c0844a213810b98b87d5bd7b3f8e680f3291fe02d967ed58259c109f8dbbb72d5df02ecfb51b97268c692fae614059e7166bc1da28399472c9813ec154b9fd4776c343aeaae789ee0e937b699e4bb97fc4d4c8bfd6210ac48ee2c544ef6e87d1ab73fdbc7c59a4def34bf7a3dc7130e74a95e8febf6a247c6bfc7072d43812ebb9202fca1ae5908e5dc0acd551e68c55ab1fb128149dacde0672aca7963875bd87b661b173a5c6ffab82c8190033cb13021e0c8624c13787f3140251e4151ee48777b4d5490f2c4a3fc318cc13b354d768d01fde8e238694f7e1004a91f3edafe89b0f90808812d58bf0fb99eca204f897b91dd9c7cd33c86c503ad8fc7f905211bf3b43c402636c6b4528b0a6713b7b7c0d3378a3803101b78e838303faf6d8d1c135515fc45bee4c27aa254d8b03f6d2dac9421c159dd7c6209074a57c7fd58aadf930f316c0d715edafc506b9318bc0b11fc2f0b2a6f1ed4b8ad574bebf06e5e353441fbb16ce6ab48a76fa64fcd04522f3055ab51c348f58db7a56018328f95042f40ff2b6375fcc5af158e65f7cf456088461c488595dd68f60f8db1a5983dcb616d289bc7e61fc0b39dbfb2375e3192902ae34fc5b0dfeec8269b29ed01eb67455be8cdc7a5cdecb97ed6ee692b43b1468425aa623c27c5531bc67626c158c5d91a28a1cfe65afa7f69f6620689479fc24fcf5d7389329314f6780870f58e4dec48dcd17d5709bc00738ab24883cb7a64faf0f0ef9b25ff5b16f1b5d986cbe2d0853c67c53a8f688d3050a77becb3d853aa05abc90c905288e8230379596d44534c0592b097e14921b1d5613e17eb86173d4feb01b385c1ff19912aaf5c938fa5dcd6fad0c69fbbcc66aa693269ad24116dd347beb10e7d5702d3415666b1d70ef0452a8a0bc4076956016089dcd3e852c5646ba274fa26fb54e57affee4ea29b917ebd9718297c67666068db50c69df4553e98ead09df292f1b74b6913e88d444de6075936d7ab9d7b971c5f08aa3a03d98b1c68c40711af221cf0599bd6b075cca71d7fb57982e924cebdf8072825609228a14ade02bc30e5767d6bdbe6b89c01e0fd7743fa179b5bf0afa961a6eda9f78a18a8b588759f13598c32af8a11e79d58dbd60612bda1ee18ba151ecfa9fe84e51a9ce7b235e248adcf9275bfde637fa93e73898e58702c26a3a415d17faae9dc8c47737cf8975ade5fe0f31fa0b2daf0c2a91e9959f49748599abd7db8fe8cfe8d576bb2f3d09ad64238d485fe516afbfe13849326963218455eebf95976f13f02d085656b6dd478ee2240d15190c000704ceb7308323abca61d9bf639a3dc182f30310725b13cf15232dd39d41059d5c87a8f0fc2f717cb13384bf743f7f77181d93559bc729c8736953b7db8bfab3c7cf52c8045917bf5d068faabb27e8de92bb1385faa270"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(1637359334602755818, 13625619742687540366, 1353784215079114869, 13374291402057849075), old_value: PHash::from_values(4210513652033271294, 7612203506764643368, 1799744277613112240, 3092055439008459644), new_root: PHash::from_values(16578736630636752170, 9201776129932763531, 4051145362860466798, 6478308873464317897), new_value: PHash::from_values(92247859529035390, 7157393019467180028, 10520993549278367133, 5847198554520078325), index: 17072600160632183378, siblings: vec![
            PHash::from_values(17224185424239847589, 15895084849485476903, 18309714393269947111, 15085661812764594494),
            PHash::from_values(6949352483475771099, 7556246637150986487, 8775278776144403263, 1145420728664023282),
            PHash::from_values(15890175002285858537, 902177235416985615, 6667969062097951766, 7148205272352828277),
            PHash::from_values(13469389522755925672, 9324667886429414701, 11384201274074848374, 1395733860194693406),
            PHash::from_values(17410955437167077186, 17890612487130298584, 1860574045064996748, 17049585811036680608),
            PHash::from_values(4889718024542706137, 7425964388725041255, 15927924213339424485, 11807789133099760572),
            PHash::from_values(3741915156660719093, 9084939003551586139, 13593193977156622013, 13811331938305503216),
            PHash::from_values(6055061427244030899, 7863468070977424803, 526572864291574577, 17776800104166338593),
            PHash::from_values(17837568354714631600, 16485946675289022809, 939057648123600736, 18058088988267270361),
            PHash::from_values(15229877279627666718, 62007447672628182, 663818841329588204, 16804369068638458418),
            PHash::from_values(14401605839314541503, 11390382961821529157, 294033886893862045, 13830393010598097193),
            PHash::from_values(17776954780736438276, 10927673427234188015, 12645219664179385051, 13895886254886232756),
            PHash::from_values(16712211704995269605, 13551110584972326162, 6764696699427144412, 1707109045164247738),
            PHash::from_values(17862818584420692174, 8617009381601276271, 4679254351899574714, 6257466195692590990),
            PHash::from_values(9504107774240006002, 3931825716162903674, 4565243987932476248, 391252125307404508),
            PHash::from_values(1854571926225260433, 6894679411950788069, 15699385641582697561, 8506458268984851379),
            PHash::from_values(10007364611492027160, 7734937195534719153, 990943495027375253, 13812804051764572112),
            PHash::from_values(15692591091321347986, 12695355711417602282, 11495500444514133116, 16719340603903031818),
            PHash::from_values(5382066353093877216, 226002967211154206, 6197229916518748787, 10688366233856157917),
            PHash::from_values(8117696944536932884, 13982315800256859878, 7314448584434864235, 10051794990882244041),
            PHash::from_values(6215840802072493521, 13062526577348765938, 9655727666856609037, 3534874722208702555)
        ] }, "eaceaac4a311b9168eb470dff6ec17bd7558522a929bc912f318388e2b079bb9fe3560b7dbbf6e3a287cb01ac2faa369b0ebab91e2f9f9187cebe9130a30e92a2a2ddcad208113e68ba14f17a346b37f6ee2c45e3e8f3838c9071acc9893e7597eae8482f0ba4701fca7339b072b54639dcde9f4e3130292f5c758051b6c2551521ac23e640feeec15000000a5e846bd629908ef2774467074af96dce74ab64d3b2c19fe3e5182cf7d095bd1db4e8db4430f7160f7e09f22482edd683f9b1cb18d0dc879f2606382155ae50fe95e0a8ef93d85dc0f3079696a2d850c169ca4978862895c752b2a88d2863363a8363c3568e2ecba2d251edb09e0678176dcc720becefc9d1eb1e3098da45e1342e77f10b923a0f1d8b891bd443948f88c27697a3c16d219a0b1616af64b9cecd959b1f0a2c4db436728a86044530e67e58670a9ae5a0bddbcfb20fda7b1dda3f58d696c02f4ed335b97c8c0e32f147ebd566603e7b9a4bcf0efb4e938b5abbfb3db0c7849e60754a34d3c518ca6206d319375ec3ac34e072130f65b82e1b3f6b0bd833fe9c58bf75961a2a627d9c9e4605f05a4f433080dd950104c42389bfa1ee5ffc8b1645bd3d6a3f4f3714bdc00ec57a918b85b360932d2c172a21c35e9bfdb883735c8dcc745b40877f4c4129e9d6c3c24439e140429b1bea42a6defbf0440facd2f6eb4f6efeac4b315e5a697db52328e49d87cafb422baddec1ad8c0e54b5e2700b4ede712b54fb947370fbcdcc29ca6ce07e15dba0adfc5a1deb017ce30a47bdc7ae5f76f718db060c49577bac1ac920a0df0408e9745fc59fcd656729f9a6eaa5fe5837abea23aa8a6903658f3b32538015b3fdc80902abc016e05918f114957c3bc19e59d864565d2ae5f599c67e60f6cdfd9b3bb86fbb9020d76181bccc5174de18ab198cddb6504586b953c97c5db89c00dd0ef80091af0b0bf921fab637448c7d9ead045b4c1f62eb07c249c9ebf38889f0aba6746b20707e8e01dbe2dd5f0b04a1e1bce5280ec220373128655c6fb0056dda846d675b4549414d265955cdaa770e64ea48b232a0bc26b5019e33b248265c945969a49267f8bd1fde8cb461a4356f2e8f8bfb66a47b50d45e69e270900865be0c1ced4650e31"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(13964700720345488831, 4073735154510326606, 3715012653220619495, 8146684174574303173), old_value: PHash::from_values(12368873365227325210, 15620365533695154002, 10122339541345475435, 1461638949903426752), new_root: PHash::from_values(136693502586914180, 4985893328693110279, 13875601892149107670, 15050593846796755333), new_value: PHash::from_values(14065609946534857419, 1895598114139880892, 10241374900927657894, 9234541136070151735), index: 4752259510428080688, siblings: vec![
            PHash::from_values(4969745978349540407, 2092466477460567232, 5950986046583760796, 14517269763115843755),
            PHash::from_values(12683105953044725074, 17968217694087569376, 2693444524548631553, 12533493909825853010),
            PHash::from_values(1817000207282398807, 10954804777957503802, 3435750594025926165, 3126423813835801842),
            PHash::from_values(8245708147816720226, 6957177592304785275, 9005453900687253908, 9506966747354954755),
            PHash::from_values(18446694395129291066, 16996328347734389929, 4513420879548025401, 12640376248160642524),
            PHash::from_values(3667454334930470042, 13770649756394885119, 14155966598963997081, 8199834322247593072),
            PHash::from_values(1105027568072108076, 15309146900781906343, 13930243556474250740, 4710663718424514935),
            PHash::from_values(9976943558619944722, 4751684365498167561, 7758223924791146112, 6928436217255219033),
            PHash::from_values(8689690515264618678, 4005529783044054906, 7890272505078874138, 4313309632125257555),
            PHash::from_values(13340834326396097316, 7959085151692681596, 7595334784677699533, 4511743470888175264),
            PHash::from_values(7506169759102233919, 17660704302205678591, 3164102874072687718, 1759519220087104320),
            PHash::from_values(15600601482313376650, 11571250433914848617, 7931207287279197234, 4544522072043768360),
            PHash::from_values(2858698181218176639, 13603081190424979791, 10770763817125487847, 14125962929345322917),
            PHash::from_values(5914571983735887468, 7001706167618092408, 17505622295887913912, 1278165286131013947),
            PHash::from_values(16971244013860580075, 18294641733111274140, 7940290270097364866, 5948016529509355402),
            PHash::from_values(4047959187458820034, 5851084347212864468, 13072020873616267704, 4633542168569486209),
            PHash::from_values(9040056726008293451, 8820649841258806869, 7943924773960010770, 16156470654489428445),
            PHash::from_values(12075292350556125246, 14884775125704107055, 5764995893347903033, 7249198899195319372),
            PHash::from_values(2517755375574474267, 2579156189063003188, 2249692203423964280, 6026871206859461241),
            PHash::from_values(9989731806795940308, 4642642893402014557, 7275184883514302863, 13998979551927283731),
            PHash::from_values(4901895491449944962, 12902881833821281669, 764657403848319270, 17104001297260891888),
            PHash::from_values(7677801184046599938, 629034576536850853, 6606611226059482187, 4722361477924561244),
            PHash::from_values(13940317303141008273, 14007378055800333104, 6625781314635453268, 93379548576021346),
            PHash::from_values(2555800747472606132, 2034646777828462238, 1399503638424574476, 5040721340631729623),
            PHash::from_values(9381704578824384924, 6057287531594488035, 5617565998650010189, 2310880659457634921),
            PHash::from_values(2236979724832074631, 13761787247163999563, 3031657652464401506, 2042486673209367588),
            PHash::from_values(13555576406643273060, 2494647703100715856, 16310068375966155660, 14016112519964085814),
            PHash::from_values(9734771040760681300, 8040043922202438988, 10197925477880233274, 12956968397526822092),
            PHash::from_values(4043616478512478557, 8689947603110264297, 12461190110965103146, 11750889895014899728),
            PHash::from_values(17541662880283972315, 12676581405275881394, 1267634415280662871, 7895622811954006055),
            PHash::from_values(16166657488062123301, 97140117503666134, 10473359848738655875, 7625725446165244664),
            PHash::from_values(4518512449047856350, 9088656549680472882, 16397064289027727368, 14829130630604358788),
            PHash::from_values(2996658280583224998, 14253611492145805149, 8139040894950891596, 8474186319828695540),
            PHash::from_values(12969290391190401939, 10403520656357643206, 8332135702831566457, 15906433951693277866),
            PHash::from_values(11360782490652825545, 6549351764622707629, 5859789107706009263, 4582631257023756297),
            PHash::from_values(4957887947016145956, 9616378235485346383, 7840779173591167689, 14180465563687275692),
            PHash::from_values(13219669549916561948, 322375719756614728, 1476176453809341431, 17938373094232149497),
            PHash::from_values(16481232068926517271, 6813300034884018885, 16909711966673821480, 11172155809106134600),
            PHash::from_values(11573160948537419538, 5709397832512445069, 16578524546616761485, 15558836363451524805),
            PHash::from_values(2543541933133693186, 297632575815189826, 634060282540776393, 3990286477385952507),
            PHash::from_values(2194043061670844362, 6568752368497736843, 4520901581679453700, 16819319819267355818),
            PHash::from_values(12745727617135048699, 15963986413331702524, 4180841068311058924, 6398724330214030398),
            PHash::from_values(347423839592498961, 4434904127836456441, 9911290487422673209, 272902757145067694)
        ] }, "bf9dd5265195ccc14eeb9b198ad08838e7e44b3b53608e33c537cc0218d60e711a472ae6ca10a7ab5297a751b1afc6d86b9bc9b12ec6798cc064de7ee1c848148405cc3004a2e5010726bee890733145d61b49a2670a90c0852100b95c73ded0cb4a693cb91533c3bc3d350671844e1aa6f7641536ac208e378e318f3cae2780309a899fd86af3412b000000375473efa215f844c03473c52cef091d9c67ee9947269652ab000a0befb377c9527ddf93aa7103b0e05ffa06cbee5bf9012cf14b860961255216b1414eeaefad57e6e0c70f4837193ab3e88de748079815aec03df63cae2ff24401e9e449632b62e72870dfa36e727b57a2d428dc8c6094a19e179cccf97c03fc8afbe287ef833ae1de4dd1d2ffffa9349cf49416dfeb398a4a7760e4a23edc65e6e239a36baf9a447f5f496ae532ff8f3c50fe2c1bbf99298bc79e1874c470ac9f1adfa9cb712ca8f3edb7d8550fa7b960b3fe0375d4f4655282b52a52c177910399b1a35f4112d7a9734e39758a09b14b42c15ff14180f61c058ebfaa6b59cf72fa07c02660b6c06dd27bfb97787a9f968f1d8096371a0042f609e17f6d53c718ed41f4db3b24532d18232a24b97c71bac3c659746ecddfe1aebe0c6869a046fa53c8ee9c3e3f6d1163a0452b68ffb32e10fe6c17f56624e5c1cc26e92b40a3c38868116b188aa3b883647880d869459468f65695a0321c44a6014f116e284a1722bf62113f7f8e908bd922ac274f29143e45dac7bce724652fa0707995a5dff611718009c46c160ee9e1c7145278bd89aea90e2b61b8a38eb6ba76f0f23b1913448ef4bc11eb6aa25a83f885eb9c5a2223ba9fe3fd82d7a462ee93316e8a8f8e0785998b52c207c3196f3d2d38d49b78a2363a3351b89963dcb92569b5819b60810da64d404be81a2fb2bb747d553e56fc4b3e697a12cc4f427e7d3e6edd81dda8755037e03eb8e3496a0e94a72fe429291d5891ce39669682386101504c94b0acfd539a641b5e72a82cddf02234bc5995e300cb23781c0dbf2383381f7952e34f6ebfa353d4417e8126a8a28a5d0338201dfb6d408f6129211ba6f66413309592bb5d46c2827bf665fa070744851dc25baa3e10b326614083db9b9c0af04e0e198f9e5ded02cf2b877f078d6aa5d1ea559dc7ba084b246222e865af5b5ca1ae78be3289419183f36dbaf475c130a394a2203464c2545344320081f35b62fb286634c04b01b453c8153d0778239ecedbe376843c1c0cda29ee24096c13d7c515385a3df4459cb17ba89b823282e39817c7eace0f544daad83b839af54d69f24a59b7e5112087eb5d2c35590b1f4b05b69596b0fbbe623cbc8f929c122a241c1dc7ce5e581c646da3dbeb141fbc50f30f67dec49e228c83cb03c60059e2364e5d8c133c83c254d34c3eafda18874c2d6a6959f9936f3afdf4f2304f868dcc6c8ccc1b66d0b35df9a661c3cf1d38e9fd24c04de598782a7aaf3a620aefac102017c3198c13a3db52fb2c738170f3b27fcaeb9f43ecaf5729ddd3c88a97112748fd5a1de3926d250d5aad54815be0d6e73e156c1c5901830ee8cc4ad95891f82a56f5e304d469de84adde21fbb43e32633b69fa64217e08a0bd7218138ee38484098dbda7cbcda65e6547d44496295db7c61b2200cfc54ce0ec4b92aef370f439dd498f5b9a759373ca83e52cfcb3c6d3a2afeaba6090790ea0b346b1a173aa0ae4356701bfdcc9d7d6b57b9ba99dad0b6adfbaf8e35aaf16859f2527525109b88033d9c6983f248c16ded1f4cd444fdae62f0e3d7485c9b22ebc1d0bd06cac4c3d814c22cbc41c22d3326ab375b748cc4d54024f7904f7031ae3a96e7c14f9cd21a249e7f1f8173024d13e19b9e4c5226b8748b48d5e28dfc333715dabea4886160984780b9b12e7fec190209ca08d1a4a3814db3b4f8d9c2f053dc012e6c566f5013d17ecd70281be73e9794c2342850c3340672104c9db06b377a2cc08fb6ca2e468586037ca17cd408ace721e8b3cd0f579e5285b046681280978bd3eaa341e57433a6ae9fb7738efbcebe1b0fc62cce50f798bddec990bf3cc54053a3e7c0e5ee0d5cc5811c76931244cd204f9059ba0cef18b3d396189a02ffa8b89ae40db999c8bc903"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(12801913726153936659, 1726466280530523034, 10791022581017213322, 16270290071266248523), old_value: PHash::from_values(15783231079166885272, 16373499348946181066, 2480614105634616056, 10767869179437454875), new_root: PHash::from_values(4604393703543786055, 16955297963207296281, 16843406571496381604, 7280797740041764183), new_value: PHash::from_values(1512318326356524715, 1976965126210784644, 9099968712383344943, 10245282575943031065), index: 17940578622850635045, siblings: vec![
            PHash::from_values(15034220633265830930, 10602018948279466489, 2693167125268254366, 9369808245699999230),
            PHash::from_values(1752864628401205540, 18031922892190177773, 14953276327090985902, 18028074404000121047),
            PHash::from_values(6723885732970145168, 13946756754375428571, 2584420699487522440, 239802777037172595),
            PHash::from_values(11841052454252411857, 6654850258247108692, 14045262051723354325, 12426803948738194396),
            PHash::from_values(737119482741854739, 5350695335942726325, 4647509990643163820, 8722383440278755667),
            PHash::from_values(1886544305034078692, 3538728293087560569, 10250113210990560183, 3887168111347294112),
            PHash::from_values(14606233015125356075, 5482554220825203611, 13968321227656021413, 14067496460957488632),
            PHash::from_values(15403491595385970409, 878585881234531793, 6150290401383564168, 8486210345807515605),
            PHash::from_values(18181486885455606688, 17348340515747893370, 15325072609225885904, 9619098034960468517),
            PHash::from_values(164661362646933560, 9500557504550327603, 4283571851211265699, 18444472255306629374),
            PHash::from_values(9483102761726476229, 11853832038444534095, 3659007416028215960, 6985979917979347054),
            PHash::from_values(6206761240786221922, 832665160191763933, 18084880915310385029, 12434684509579842352),
            PHash::from_values(16580008141095154559, 5748102140716436032, 11997893570137237631, 12875866217844957240),
            PHash::from_values(4078168091595318474, 12859507083472680363, 2127750595163766185, 7853954552686940054),
            PHash::from_values(13712719412927005125, 7883032838046354430, 17977712603768007719, 7620187584914092410),
            PHash::from_values(2230044526383242591, 6303003981976645400, 5089731594838258568, 6713088477389930979),
            PHash::from_values(496263803086502747, 10202756765036492649, 3159341125659216000, 10726695900792999546),
            PHash::from_values(7789202814208809988, 8207734569698586439, 836522656016578143, 11085225813940568640),
            PHash::from_values(10837325498089982310, 5954514997817949503, 13713256575798297075, 4303383153786018056),
            PHash::from_values(18362675578570731161, 486629419988157166, 939072845734144067, 11521062459339083331),
            PHash::from_values(8324307761782601682, 6851256402842016313, 16759386095509239406, 18174941407003398739),
            PHash::from_values(6635741192379013250, 4483219318405491513, 587889379326937026, 11811685988462843135),
            PHash::from_values(4340622976831378283, 10888417281494827765, 765880929197232097, 6747416357387246869),
            PHash::from_values(10562777110277973202, 14148196644921550903, 15718892318476927956, 4080425594653527047),
            PHash::from_values(15795840058027999796, 16042300996535043491, 15293497090197555241, 7443500039956056875),
            PHash::from_values(12775975704595826384, 13137423042972469647, 4342093555787165118, 7225417773167113121),
            PHash::from_values(10497920521580709749, 15970368141225534260, 14192737213318607246, 11854737462304555397),
            PHash::from_values(10560581044114503291, 7045893477597990555, 4689340102658846922, 9348254001771160975),
            PHash::from_values(13995845083452511997, 607904535172937915, 1892559094170208001, 15304780368765452651),
            PHash::from_values(9374420703239911638, 9229602985203664898, 11294058857746062811, 11925391468827342389),
            PHash::from_values(8834867004121087194, 17249079954088863684, 10361810698189153755, 6420231585586733442),
            PHash::from_values(15739809300115783473, 11640677514199709174, 81050874562349108, 17652465214454909580),
            PHash::from_values(8820661238240735013, 5227801353665671389, 16305371999596718086, 12922415625027352032),
            PHash::from_values(16031436937195640562, 601464198963086243, 10662846455260861435, 10478476562265548651),
            PHash::from_values(17257670413781714804, 7661015253928425715, 15289623560207155486, 10512008126713603527),
            PHash::from_values(15565390134852466446, 18153470370041946824, 6025841617249718937, 9133796712042521772),
            PHash::from_values(2888489505111899868, 10279172552324011599, 9388292140606252140, 12776905264134958659),
            PHash::from_values(14484844489392113424, 4834083596908730681, 14091676564209135036, 9528593001726284586),
            PHash::from_values(3295559745590849291, 9031067220683429080, 14116580068736070476, 5819536047478154875)
        ] }, "134f9adcb488a9b19a33b657efa3f5178af9bf38dd69c1954bc763ba9daecbe198bda5190b4d09dbcadb0648e85a3ae3f8b22cdf62e96c221b163fd4f7276f9547cac5a1ad17e63f1905e01daa514deba49c855d09cdbfe957fda720f8960a65ab3ecb5581d5fc14840d21d14e976f1b2f31c7885495497e19599592388e2e8e2595fa4734bdf9f827000000127ca8e00248a4d0f97928c20ff021939ece5f3e3b0d6025fe7579c2f43e0882247133ab176d5318edd93a4e55423efaae1b84f897b584cfd740bd52279630fa90a50010730a505ddbc9530160d58cc188ce1eefeeb4dd2373ef73ed5af35303d17b7b7678de53a454483c0c0dc75a5cd5a03eca6bcbeac2dc2bf6f159e074ac1312d99d43c63a0ab5a234100f7d414aac625d82b6457f405399909886210c79e4a997d20c5a2e1a79c31b32a2161c31b783a170a8b73f8ea0df145bcdfef1352b2e21458ac3b3ca9bd31a1a04f2154ca545fc322672d9c1f8956f9a7fc939c3e91eb2abfe31c4d5d165a83b345d310c8843f6cf88385a55d50f1aff5813c575a0330120fe9d51fc7a90ab9bc8afc1f0d048faa55798add4250a7ad9b2e67d853860cd0ca3fe480233d5e4dab6c2d883a3564f41e74d723bfe80190fcbedf7ffc57f3bd9b7bf9a834f89a1466f4581a498bae1cedb67c7326ee82bdbb82ff36062bbb9b276d82256dde512328d388e0b851751ea5f67fafa30138fffaddf90ac7fb30f478f0518e640ca1036715cc54f7f28f96ca21481a638e0191a1b44b0b2ca24dfb145909838ab3502518f2576b2a9bd5c9be449871d968ff7ba0ddafe6cc5011e28a75d4dbefe0b7ea09928666d27aca7f55caa7df97a71a5283c58c0695f9d6074aeb5f21e182f9713bac4785788b36a40eb5ba246e341981867ae295d5bfbdab14c15e30669b7b6a53879978d804833cf033cd82b7ace67dc16e1dc94049c63c8b0ce186c47ef93cd1abbe7715f366f6eecec9b0b4002eb4e25a2d69966c9ef341fea65963fbdac96d7afa252f3413f2233464fbe08d9d0952db0b83b99ee722a2654d5feee02a613e1dac00643e8321cc741080d438efefb4309e39fd2371426cee1857339da841c668d145f6ef672dcdb4c95e853d2f929ea5c3afc82982df174e3165c396bba8b3798373ec2c70196469a2808ff54c954d389eba36bd3ee8d99fd3c3cf542b905d46d1b97e10f0cb5a5f4a00a151dba7d6da3a35dd2e4be5bd18596923728ec60e37d58c4d4036f0948b924da074cbc957595a0383402a5c3d71836dba3c55db6c2b3a1de2908b23a936a3dd42bcb2f57d99f4c67d086749b36624db18fc9670ca78051b6beed34661537423ca1736bcb2ed7456475071a11181bb09134a3f6b53525a2dd8eb152964cbbf6c485c12db2e97c84a47b362bdc81b88e929b4e7881c90ac861ca70f969fae113418fa5b1457cabbb81fd969542f33a3bc2bbf85434f4b56f080147730c78b8431a6b01a33da88065d4d6b8ae37f6a118820208f3b603231680dbdd4e50b18ebc9c3576ed825b807fa5dafc742abbc09b7ac427c725d40a61efdb256847ee8bcc8f82e1a37a9c3e1959317fca552a096fdaf635c03286fe8ba13408064b57f31f018c4a86f59527faf4256f658da948697add708c11a2e18c48062890ae715148e2e075b6898ba455b3f2569fc8f41a7bdea3434f9480d45808fb535b5c5b0afa936b271881ea066b9174473a68ce8f7feff3b8409dc864516a1e4197bf9ea72fd4c7a5c83cb227e2910e3740d2db5f03d8c8e2edce1e15eefb9952ef4c0617a053ace4ec77b7c3c17edc7ea3a9e6f915284fd63796f9f4a68e6c646de8f5e94982432e958da4af50b110c7fdb0518104c9399949586b1d1643bced619b2cb18fc32a132bb5d95c3c840bef04c4202ebc2dd89482dfc9cb547d4c735f98c72ae8c37b2684b33325c350"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(8428495392325130578, 13633775954877962534, 632339465597303549, 2316122155317306754), old_value: PHash::from_values(5042161497807583381, 18070229412102430289, 13645291490957277354, 15545000856152674964), new_root: PHash::from_values(13649699067207301942, 6926478782442593094, 8978331131569548930, 11537082662409206665), new_value: PHash::from_values(8029473421519182193, 8833291425353062180, 1448202909793909623, 8341867230960549683), index: 10064509807496061050, siblings: vec![
            PHash::from_values(4573530568077651198, 16771249627059263704, 453938038203705030, 3593685288377980370),
            PHash::from_values(15863422240457295700, 5499753752808223447, 18135330364386010728, 15011829317411245553),
            PHash::from_values(14057256288464268724, 17853621061852179760, 4096673477320879228, 8140631722567722339),
            PHash::from_values(5639569407119940238, 1585402933455488384, 5892642438790426477, 17687733341669798306),
            PHash::from_values(10518028685771209601, 10705370989071641955, 8404825163357743935, 11930825589768220024),
            PHash::from_values(17466577631023403389, 15522781763610682860, 11379491787443720722, 5807956273849263730),
            PHash::from_values(18018284155630670817, 3573431852530931072, 17883140634514223350, 16752204837777839402),
            PHash::from_values(1439882601818083924, 207831433302784407, 11585553415607440301, 7572059668404812316),
            PHash::from_values(6842287712704212750, 16088716141120890733, 12809396499987191334, 18188692679525818787),
            PHash::from_values(9149892244539374422, 8412962466657250450, 3308375997016787385, 11536843087753848792),
            PHash::from_values(15325851600827928141, 8312129789310798566, 15029604423902604483, 11998340403357861924),
            PHash::from_values(8699542711714093678, 8104407778355073846, 15301388588029659767, 2818422121105094159),
            PHash::from_values(10677404083773725724, 11808041409099752995, 17179632529267399157, 15550876459453042646),
            PHash::from_values(18113748168371160058, 5791018461525804020, 18323235760736751497, 16729930220346384072),
            PHash::from_values(6251879955530449825, 16661994214935407034, 14786081579347069833, 18401647922839613157),
            PHash::from_values(6019198180004002696, 4482963376253448098, 6397438691458723704, 14015921840520418090),
            PHash::from_values(15662471194691840666, 3123300224086825040, 11926021616268595628, 1655746680901891148),
            PHash::from_values(6924037358641115138, 3947979931935648312, 6563706996138536611, 14490196688223007867),
            PHash::from_values(6784077910211179149, 1371795697107871578, 917163629153922863, 7529375142973959233),
            PHash::from_values(15502199036269374211, 1596950441946536728, 3675773977010283158, 14673287439122137089),
            PHash::from_values(846707789559350584, 11348718845380485839, 11572211848247009937, 8720640052303374540),
            PHash::from_values(9487863514677445611, 1705326453398420896, 8498843144271615786, 4686438560223073858),
            PHash::from_values(13064860619501317701, 14021743934139493660, 1938707659403542377, 2045623599254432203),
            PHash::from_values(10319943718465785297, 7773229768965581984, 15499520946335671199, 4032561939125621234),
            PHash::from_values(12789136070012952799, 2971813453989204173, 7028579085498537309, 16646579297660395155),
            PHash::from_values(11654914232420412108, 12528545258259086971, 777828802249909104, 9111666921185965260),
            PHash::from_values(528674516524376685, 7385628995438168120, 13720845654420100294, 1918092545516841875),
            PHash::from_values(17585387945483625740, 2380672929603953186, 2361522393698779033, 13725978835433316438),
            PHash::from_values(11929566181563890617, 10048824565489207665, 11199302895971592248, 17423796172912049116)
        ] }, "52598e3ae707f8742659c301ffe634bdfd3a63c86485c60882a51934d484242095f8f8f02a5bf945515e2efee859c6faaa382baf50d05dbd94921ff0eaefbad7363bdf7ffb786dbd465bc52bc1cb1f6082ae084d9870997c89fb372d8ef31ba0715917ef886b6e6f2457ac25c027967a77fbf3a0df0c191433ffdfa80c44c4737ae03c8a5852ac8b1d000000feaca8efd171783fd818458cad72bfe8c6662b9d3db64c06d21551c8ba55df3154077dcc7a3226dcd7724134e60c534c6866959de1a2adfbf18d17653abb54d0b4ed89a61d6815c330ad2162c3cdc4f77cac7990d24eda3863e5ecb66b55f9708e5a8bfd7ec6434e80057a72917b00166daf7ed813dfc651a2b10fb8c27377f581fbc2e05c8bf791632d63f0311e91943feb3395f4efa374786d4663a9ce92a57d11ef42d0bf65f2ec25ed51c5ff6bd712d20e537d13ec9d7266c98d75019a50e1536a7ef9cd0dfa80152c4756619731f6f0927ca8ad2df82a1554008bc97be854d2a1f7987dfb1397392c63965de202ad5398d77227c8a01cba5461265c15690e2fc1366cb0f45e6da79ab3169a46df2656dee83f1ec4b1a361e2cb9f376bfc56fbdea884f2fa7e92accc25cad8c074b9499dd570b6e92dd827fddaa9191ba04d4eb3c3d45cb0d4e60ad0fa009e5a73c3ac5ae197e193d024c85ce406ab82a66e9a0e1001fcba783653c477efa37870774ab9bfd97359d40f76928bfc0b1d271c5ca36071c22d9423667e921997dea3f599ba86c3506aeed6cfae6fbfcfcfd7fa43a506fdf560fbf483f9ce9bd45d5089cf72fed73549fec89ed17ce5a62ce8a103c717b223c356baa9d69e754b3be789cbed3cdbb632cde5eea82a4ac95fff88fbd087da7c8853a22fac5e70af363e78afbc449844c8582ad3db87a78e82c29a2a657891465cd950d8977f0131582bacd1512579bd81a54c743071d564fa16027056e54a1f1760382a65afd40aca36a36e95aabcf8165b7bf412971d8517c98d32b66eeae2255e5a27861eeb9809132fafa01c766bba0c416c9ed9ccb67d68032b3daae3df22d7185b2048f781291696a252fef4f80233018013f82efda1cb38c53da13f1cc00bcf62af6aa9bf7e9d916254205dc198a0cc289673ecef0579eb03bd0599a9ab83a0bde3c85f89aa172ad71298cff4f1754216ca6b0a93094145ae5d4983b54fb51c6ddf55d13d97c269bf133258ace71acb69b749d383631cd14d2d7122ce378fa06caf604a0fe06b9f6310432e5c19d7f2d157dcb789f637dfe041f57e237cb1cdd0c04f97003e295d55e17270878a61935e6b82ac8704e7cc2a1077be92bea17bfeef868855dead70632cae2c67cb0acc74f704ca24737e6da23cf7ab3a560738c8eacb70067f66c614ac316d3c6abe932bdbf5016f9e1a0ce5fc3f2ad90bf422a26e876ad9092199bf8bed1ad0c5205660880807797cbeb9fba0903c558ea57109348cb398748b38e863bea5ea6b9bdcbb3bd54dc2cdf1"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(8720879378864965806, 3860360479500462891, 17433902499551903293, 6328586152488421210), old_value: PHash::from_values(691682959585249319, 9074411004429809669, 13089011693076021774, 229421357518332590), new_root: PHash::from_values(9777259083923867006, 7836743993153333388, 17278071742689413336, 2732047524030229664), new_value: PHash::from_values(5299977073734718925, 13878289337741850105, 14014825254823529382, 11510541179510140799), index: 4322780378163020223, siblings: vec![
            PHash::from_values(14982114819793493754, 15269535918182213943, 2181568914874351664, 12004651229996495306),
            PHash::from_values(2722960076804773805, 7730145632923270466, 11950365668063509524, 61518454664167445),
            PHash::from_values(16943381691705828782, 2048086031024059750, 17033560747916234944, 18126388611776428875),
            PHash::from_values(13184519646583402693, 17877946554544563755, 14932138177494864632, 15037767530691103428),
            PHash::from_values(1860400991080667315, 9959830435071782071, 7705531008190097056, 7333461187670825773),
            PHash::from_values(11802779989428469794, 14285829438884740437, 2881319720840410439, 6418478197677561673),
            PHash::from_values(8369979932520593486, 2217438998332157188, 2833989618111787205, 14367088636873217257),
            PHash::from_values(450760965626743755, 1544800353464145436, 8113403238595867363, 11700663987566787177),
            PHash::from_values(14873282109894366284, 9436401001866937158, 13193335328597617374, 9687905808939519116),
            PHash::from_values(14154317196704009031, 233226499119671500, 15724424344046602299, 6058869429341394053),
            PHash::from_values(13731595636313226313, 203959303986135101, 9363806157487883635, 10184069409177025812),
            PHash::from_values(18440854988816218582, 2428221366446007839, 6081489326173024089, 17647115080544169943),
            PHash::from_values(13894431291667294510, 4600491902270376945, 12348431598934302310, 4875987315828328992),
            PHash::from_values(4047593468216972818, 3196707944608089803, 13487816313915229607, 3996343338525498020),
            PHash::from_values(9263193855905717029, 10704961211754292886, 3823117936967716342, 16763367972514946795),
            PHash::from_values(4845969871607462387, 9783684340023768649, 4342271394872919395, 13390533048444737787),
            PHash::from_values(11779843389649754974, 2835027726153906690, 8883100934649083417, 1669370937599006842),
            PHash::from_values(4784549997414696031, 17780813587099312414, 11243559754022826773, 10256121306100436383),
            PHash::from_values(4121616489964198844, 5413170295822991293, 6277801658204958214, 6183788120348001868),
            PHash::from_values(1723434428249241009, 7143514917832037507, 13209393846831906472, 4343202935143269123),
            PHash::from_values(13741491235368798335, 12767860081998326522, 3580067519469713373, 7965667881660781551),
            PHash::from_values(14098386125469064626, 12117578521876835520, 8410439053397406367, 3574326295483779483),
            PHash::from_values(13482513899542795220, 16051147314829380485, 11216066549194729365, 13681063940954536087),
            PHash::from_values(11044316390240296546, 4650124781455667841, 5144590636342661414, 12695277188543770885),
            PHash::from_values(6871762596891971505, 12492076736765943643, 16820198988177071580, 6220449398431378680),
            PHash::from_values(13032801394701225473, 6845165202711571653, 18254824873849120677, 7282637505601409803),
            PHash::from_values(8921984034837240173, 1946736008641865189, 547618075322647864, 9563173905695984023)
        ] }, "ae88460297c906792beb942d67c192353dfe955ef4a9f1f15a47874d93a7d357270845affc5999090538eff0bac8ee7d0e02bb4ac982a5b5aea2c45682112f037e453eae55cdaf878ca8941324b5c16cd888b7f2b40ac8efa0ac4e83bf2eea25cd15ac6d114d8d49f9b531529f9699c0a60beec650a97ec27f2f35a137a8bd9fbf816fd2d999fd3b1b000000fa1ee8c90c2aebcf37a95120044ae8d330c01ea05e7d461ecab165b8b01699a6add78453c3e5c92542bd6d407ffe466b14fcf264423ad8a515806365b58eda00aea5fbf3e0fb22eb66f5a0dc64436c1cc09095a7405d63ec4bbb9e9967de8dfbc530c394c3d2f8b62b260c81ab391bf8f852a1fe8e9c39cfc40abf49e5e1b0d0b3d82535d878d119b7ec93e1026d388aa0a6ed54a08bef6a2ddb3b8918b0c5652200f9d7dde5cba355fd8a622f7641c64735052d0581fc274917290bea0313594eb8090f6724287404adaf3e05edc51ec5b0b2e48a5a5427e91461c1fe2662c7cb4bcbc2b56c41061cd6209dbc3b7015e3b202444299987069ba1f67e71b61a24c146de4468368ce46436b0ab7d4f482de2aac7f942418b78c8c4827015b728647cbbe637f3c6ec4cc683ce843963c033b08671ca16038da85145e0ca56d155449fcc0657a6d90be3dc0ba06e89bd4027345aeb216ecf281143deb8d2b15558dd679e192e813ebff1f2607af77c6b221596fdf2f52ca6554d72f46d6aa25e7f42ea9e6d7a4efd2c0f10be3ba023bd83f661eb04b1d715eab200a4231a1fcaa4312964374d0f02b38cbc60851f0fc5c2ca7c5a2da79592ebba49a4fc517dd7537255bd7c2bb798d809626f33881a98f94f68d620782710e35ebdee9d85a72a3e8f3796855ec5740434936ab3112a1c6876385bdc9d3d8423cfb58ad89dcbad4b95e9bce8d26697aa3027ac941b20a582719f6b2413c1d477b7a18f3e505cc2a175fc4ff7ddf2266421e617e2cc023c2f615b3687d0626099c9f8d6e17fd0f558ebc5bb5405cec3239bdbf392fb4711f4b062eaacf583b1f574c869f47883ad155b17579397bdeea1783141545f8dc2263a87ea5a2b73151b70303a6e80e28463c7f084d187995b3befa6a66f9188d30b1ddf7e7e170f4ae31ef132105bcbc8b6eb21de1127c87a7c3c02c5fc676492aa89f32d336c2e1b7749b09a601d48e9a31d4d3834df5821bbb85cbdeb17021c1de95a7e4e91979a79b9738003e2be7dcbd621e4cdb3d4b459981f2e7efd98f884026510132ed4165470571452c57af2eb0b1cf8f78ac675d5f5bdfda319bc55caddcddadcddc596de9f86ccb40c579535601ce6157d1cfddb4c5ec7c107ce9fe5ea5e7bd2a812a56fd0b134fed392011656d192e803541d17be5658fea1532041b388530f4bc87990797494bd6ff37b784"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(17969064115953028442, 7699378782882150337, 10709366543766626362, 7873558819665973582), old_value: PHash::from_values(1619022548104214573, 16206503899621437748, 6016635093771475845, 7652352988779073578), new_root: PHash::from_values(2546382509925472058, 3879970909014900888, 11313400168226437903, 11109932453670318850), new_value: PHash::from_values(16682989870791667424, 4702269246413237166, 9783905445209926477, 6669562822312922259), index: 9293947635510478342, siblings: vec![
            PHash::from_values(14979749170300739708, 9084995996535332794, 754390674218350851, 10577338306987193115),
            PHash::from_values(13972882630636897560, 9890120880063216255, 12087804805743605961, 8618390325322916420),
            PHash::from_values(8132420257284772207, 16120666430991481895, 12395878852667698190, 5143745377275110968),
            PHash::from_values(3478207747914743649, 6647741199034744699, 16212951941983714019, 8380526790429572524),
            PHash::from_values(7138293041154091071, 15095656993342615539, 4920973514610269799, 3575122229023371945),
            PHash::from_values(9731903176347199299, 17575707425846060841, 7863529142059727358, 9609144009256108613),
            PHash::from_values(1073019451840333715, 16514066627927406732, 120947439628706022, 16021227136798590542),
            PHash::from_values(299661148163186614, 15172930092357418063, 18393568217677207511, 13217682502149669159),
            PHash::from_values(18025005316929455027, 15268806035161595684, 6733357724131302130, 14094215101003540620),
            PHash::from_values(15605134837245441823, 901810542639370938, 8939597772033520155, 15080270320565435716),
            PHash::from_values(8606555126312571786, 5979311294822340896, 14094987176458286233, 9840579948373223155),
            PHash::from_values(18176189685324510293, 1730473405454145897, 14001290727752923958, 5055127445160606704),
            PHash::from_values(1624608570339930707, 9629600427445920773, 1329396691664285414, 1330494837309046350),
            PHash::from_values(2467935367408459660, 8595646678015891473, 17249788817660910270, 7030468666447055038)
        ] }, "5a4d99f99bf05ef9c1b7dec035b0d96a3aa0a98221509f944e9155d40780446d2d7819f76dec77163431eb536e11e9e085db6583bd617f532a5013d87f9e326a3a1760c66691562398c0ae1afc6cd8350f3bfb148345019d02739a23b4682e9ae02efaafe5e285e7ae6bb446f7d041414d6bbf412a6ac787930c1dcf0c0c8f5c0606af0f22bcfa800e0000007c603a1881c2e2cfba9f5577b963147e03f9a63e5222780a1b731a292641ca9218855697b8a6e9c17f7ad7518ac44089c9789b486d82c0a7442289b456ac9a776f51a6f72229dc7027bccf41b51cb8df0eec08ec230207ac38668afb2a416247613f78b5841345307bff31376685415ce33a6b2ee4f9ffe0acfd32c6b69c4d743fe8a15cb34f1063f3ef53230e8c7ed1675e73cf56cf4a44a9728ab9b9629d3143a7ab8660aa0e8729e7bfa1c874e9f3fef9668917de206d458248a390895a85930707a08121e40e8cf8be521ac02de5e6e08f370eb1ad014e86ba6232d556deb69f40013a9c28044f7ccc84871391d2d7979036d71443ff2701879634a46eb7b3831bced5ae25fa24bf25fe30b2e5d3f29a7adc2cb1715d8c2843c3f5b598c31f771676749390d8bad2b818e9df830c1b72ee44cfd40f7c443d2b36f5e147d18a93adb349a0707720d95d61f1c7fa5299747b9628749bc3f3269e4e53c3908855f4e29b37cc3efc69d95ad164e0031836fbae20bc934ec2f03b20cfa06b274653b22a1ee3c48b160524dda69136a385e6ae3a643ff772124efe4b5901de76128c1f011724de3f221158e7a91cdf4977be1a2f4f898f63efbe4817cc003e9161"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(9822579079309131321, 3006829359119746582, 1011698913004109639, 10025182811970743193), old_value: PHash::from_values(12319741082501734029, 4645247400128167064, 13209030617306516528, 207555857080812300), new_root: PHash::from_values(6828556804230657645, 15284225778666414143, 7210166987006750739, 4451973899967370977), new_value: PHash::from_values(4840524267553313114, 7243436599801506017, 14064722302295422542, 240539259327072481), index: 16412952912575805116, siblings: vec![
            PHash::from_values(3028765295624807251, 8343283368720725275, 8930919865478094343, 4800721789492734171),
            PHash::from_values(16612852134084956681, 5129084812938260233, 3416516699350635272, 7707463242518120444),
            PHash::from_values(17547813839879644248, 14219008738794662588, 198567904200806816, 6324761964702172376),
            PHash::from_values(15706722452950358864, 3140990694615015664, 2999597256237282571, 475200228799958121),
            PHash::from_values(6381771728310904393, 11996544764471756428, 7503486382560847313, 2367228566353123029),
            PHash::from_values(9449447913795507755, 12271245348066093903, 8521756499684715760, 4048246059556042417),
            PHash::from_values(6637386620525474409, 15261914271626597205, 12718789349305003200, 46929132426796242),
            PHash::from_values(12234421147161385252, 8730087681833379470, 1637710511198541002, 6515564958525455964),
            PHash::from_values(5174923968222078943, 1886163877252657960, 4541562960048571906, 5834446648827575827),
            PHash::from_values(730341041506147523, 15175112636997942025, 10350211776979201336, 10407002509142633252),
            PHash::from_values(1389204304002641120, 5190399085444598088, 1393319697122182404, 12711581882237560585),
            PHash::from_values(16458375075688638256, 15086293713923092048, 9427587335026085615, 1149423972315423859),
            PHash::from_values(18168678859833545561, 15573608175384007370, 13431818729257822325, 7659046844699469422),
            PHash::from_values(12481703851359671741, 3193248627497099644, 3329219775586915101, 15699460234928208444),
            PHash::from_values(17747084906180934650, 2326181194233036537, 6570055168066396455, 8951520246183018668),
            PHash::from_values(13918437459602290204, 3716732483385194185, 12751344433779882576, 7824310621918048920),
            PHash::from_values(17136262863653219161, 15531215414446202707, 16420923417740455299, 10576761987151869781),
            PHash::from_values(17447200362115817186, 1253747435106950715, 11056854955352940227, 14305889735845051091),
            PHash::from_values(3525003369235626766, 17359854736457275832, 10481599539945366981, 28417345072665835),
            PHash::from_values(5067255579668557674, 9886484959458973202, 3444938347207475496, 13222681167212961921),
            PHash::from_values(11921643140030496173, 2027005005504766985, 9401388064449125757, 1315838010128609231),
            PHash::from_values(4953022721149025705, 9742580270145587594, 1198541808107436674, 9839158866283123689),
            PHash::from_values(10860113010839453328, 2307913748961753510, 16173665907246385434, 8986258339266283824),
            PHash::from_values(4327082664315198086, 10210922090616453967, 17411419895711074583, 14811728678286173478),
            PHash::from_values(347722313627239875, 11640246164543328321, 16605743687325053950, 17631194879398036619),
            PHash::from_values(7889827156473832128, 14106270156843279217, 4598698715821304908, 3504095641534989616),
            PHash::from_values(9481780357223766936, 7983490964608185818, 6548987858984828739, 13698265066895284734),
            PHash::from_values(11263643414378996654, 8500154122039778367, 3873996248909494234, 11512942292024324110),
            PHash::from_values(15696742819320329837, 602852742284086148, 17870580683178225334, 9466247797752701485),
            PHash::from_values(3531545146723080762, 7855640680666318602, 1988926803652673731, 2697652177894085190),
            PHash::from_values(13318248428668286045, 12107341603912560273, 13432590135937465994, 7514101552991932482)
        ] }, "397e6760a1cf508816468c0a5f67ba29473f4219cd460a0e992bdedba69a208b8d5e4de33d83f8aa983c721ae63b7740304cd0ab5ce74fb70c835accf362e1026db6bef43be8c35e3fa047cc5d7a1cd41330c96faca80f64e196dda8ac96c83d5a512cd62cff2c43e1683bcc35db85644e36d5746aee2fc3e1c8b9922e915603bc364be5b685c6e31f0000005363bf41fd55082a1bf505ed044cc973071e4db34c00f17bdb28314008979f420952394effb48ce6092f095a762b2e470813fc29d6e7692ffc47acb1fb68f66a58a4b50eb75b86f3bcea07c61c1154c5a0d1aef17474c102d884f9327f11c657501bc269da7cf9d9f0e05523650a972b0b7542dfcfb5a029694cce221740980649269a27939b90588c466922e7497ca6d12585191cbd2168d596a2c7d615da202b5656f1cf2e23834feb24d3a0384caaf06c15e2625c4376b17636b757422e3869f25909f7bb1c5c5593c4402b36cdd3c0ac58b2863782b0d29cea1bccb9a60024d9146d3665c9a98e26b11d7e802779ca94e9700851ba165c7ee40fcfef6b5adf278861ee05d1472873d1930d002d1a0246c42e73df063f13fe559c501ef850c3dcdcc74eb1220a09bbcdca8ad498d238ede8fcc556a38f24ab0bb6a4196d90e06c8544f4714713480970e27700084804c585e5e110561309a70f805f9c68b03067905eeee467e4502e98c333485dd1ef8e3351bb84d58273e42d4e0393f30f59138746291d24fcca12e27c1f9220d875e8d92cf86767ba6e6663a086664a6abd15eb9b85eb37ad7ce17749b5b2502c1d531037bfc3332e3c3a4484e7afdfd9fa7b9cafb14f4af6f93e74b5784148202721519f5d862d5bacc074993c303a7c1cb61560203928c1c9765465807c943350ba1af833e0f5b098b2bd3f0e89956c59abc45d483cd0ed531f23ac21f689d7832d50bed8d6e2e355b70a3efd34c892e2defa444ae820f23b5e9b4ba6346611c35ed40a00d77199d37af33cebba88c60e3b5857e353eb30b819eb06e897eaf0c56557683f1f7691eb1484be6cf564006aaf422c1a8252461256cb95b0d9338928416cba2ce1ce2f81e0f9fd766680b7ad7d7db4452f72a509e40c1f505e211c7d5d1649a2707882cf2facd7b2cb4212a9bd8632ecabbc448ac9c1252399348782bab2a06c13a210e9d370d9dbb68b8890feae773edfb696a6f91aab535b07201a49446d736774e030c9db2b599ab57c861a42e0c1e20c3c4ffb61a88a7bb48d1709073f25caa1f126a5b6cac1d48dcdc3853a189a5bd3044150b5c736768aa1fef33112e77373e68bc434285496aef4c062da28ff4b7e6d7163562cf889c3c34cec92f91ddcd13f3005b0a46b0ca130985b998eff0c9683daf502e5bb0ecb6e43ff227dc2ade25afe996f7780031abeae63ba0e0280509c3fdc4064239df675da3772251033c3350e70ae330430c69f6d7640e46d08d6d9848bb60360c35d08b6aecbee720e01f82da2dfbc37de5e833a1aaf9a999102310a4739fe93d7046dc380f8df63169a1b4692efee5cfc6f255d742dfd61ecd3b8912e84930aeb05a88afef7498f256aba42904b108d734768"),
            (DeltaMerkleProofCore { old_root: PHash::from_values(10445970190753850611, 12082247597015245336, 2892900912032576125, 2042903571242067077), old_value: PHash::from_values(6417308248478388365, 11861664720732155447, 8839366229105345825, 420422469105557837), new_root: PHash::from_values(15907576174758698476, 1463763059769724119, 15618158456931492364, 17482801162671405339), new_value: PHash::from_values(601039979443227404, 6151354248242201377, 8172113348320151403, 9727131247120106642), index: 6011120759220873378, siblings: vec![
            PHash::from_values(11951390726306217910, 2044589486450583827, 2891228822928518425, 6709713490013747957),
            PHash::from_values(11937848963300766520, 7402537868053475898, 9503726425055986274, 9050234385852973278),
            PHash::from_values(4919689136624790616, 8121838658902015369, 7667280966006651209, 430678142585155763),
            PHash::from_values(5344741550470156662, 1685012220514550256, 1192913350397670026, 15764855524492939482),
            PHash::from_values(1493742732439357849, 9311024339734789286, 3215038065751041803, 10990364075750937470),
            PHash::from_values(10192536931794487701, 14036973639002484247, 4199223608468464196, 4038208265803150580),
            PHash::from_values(10393741190869243320, 2272230619971936070, 12539465844179689592, 4925451703981487409),
            PHash::from_values(16082377182395386455, 8214744305113928155, 9795696836060052108, 13871723413159794075),
            PHash::from_values(4363660999880158192, 7311961482587945050, 536242406278328420, 399689360911995719),
            PHash::from_values(5025930860713423793, 316659944647528209, 10409196378886444289, 6206645757334698801),
            PHash::from_values(15725973676394943045, 5818576018465345953, 2258727122594458530, 443478064986719269),
            PHash::from_values(15965315346697852098, 7622245973336559514, 7498696587969563698, 5864652613576874751)
        ] }, "f3e4331a8b8af790182269cc2cc4aca77df21a600da6252885a4426af9d9591c8d10bd04dadb0e5937ee05bc37199da42185689dc0bcab7a4d21a11602a4d505ec9df5bd3f10c3dcd7cce95cbf5450140c222a375ed8bed81bb9d09307639ff20c8b8546ad525708210311f618005e556bc7d9e6ca2d69719244322c55b6fd86a22856737bca6b530c000000b63f615d8bdedba513a962234ed75f1c196d06cb4bb51f28f57aea9cdeb01d5d38b3cef761c2aba53a72b47df818bb666282f4a7d404e483dec0ca4639e4987d586cde41343f464489bde39a3a91b67049b9f0636aa7676ab33050257d13fa0576510b5c1f562c4af041f6ddaf5d62178a3246325f148e10da90c1e09204c8da9989ded819d7ba14a67ce8184e6737810b277338161c9e2c7e5359bfe59d85989509a94b562a738d17ee43522759cdc24462329b9fa3463af4343ebc05990a38b8551b718bfc3d90465f31c7b595881f78607993bf2105ae31b528863ab85a44574a86dcd61430dfdb91fa026ca200728cfac6605f4ef1879bd5dbdff24282c0f02b154a8fd68e3c5a38fe5c3a4e79656470b89ba01d71074793a9295bfb8b05b1337f427db1bf45118f4fbb8a0065040115cfd0f4e4749031bb9e9c6e6f22564512aa28bde13ddaa1d13b870fbcbf50a26bc8ca599c581f25043651f38c2706c294044fb83190dd9a8f600f54a8c769320c5c24d1b81068ffda50d37a6e6351")
        ];
        for (proof, expected_hex) in test_cases {
            check_test_case_dmp(&proof, &hex::decode(&expected_hex).unwrap());
        }
        for _ in 0..1337 {
            let test_case: DeltaMerkleProofCore<PHash> = QPGenRandom::qp_rand_gen();
            let test_ser = test_case.clone().psy_ser_into_bytes_vec().unwrap();
            check_test_case_dmp(&test_case, &test_ser);
        }
    }
    #[test]
    fn check_test_cases_merkle_proof() {
        let test_cases = vec![
            (MerkleProofCore { root: PHash::from_values(0, 0, 0, 0), value: PHash::from_values(0, 0, 0, 0), index: 0, siblings: vec![] }, "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
            (MerkleProofCore { root: PHash::from_values(0, 0, 0, 0), value: PHash::from_values(0, 0, 0, 0), index: 1, siblings: vec![] }, "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000"),
            (MerkleProofCore { root: PHash::from_values(0, 0, 0, 0), value: PHash::from_values(0, 0, 0, 0), index: 65535, siblings: vec![] }, "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffff00000000000000000000"),
            (MerkleProofCore { root: PHash::from_values(0, 0, 0, 0), value: PHash::from_values(0, 0, 0, 0), index: 4294967295, siblings: vec![] }, "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0000000000000000"),
            (MerkleProofCore { root: PHash::from_values(0, 0, 0, 0), value: PHash::from_values(0, 0, 0, 0), index: 18446744072296984321, siblings: vec![] }, "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001efcdabffffffff00000000"),
            (MerkleProofCore { root: PHash::from_values(0, 0, 0, 0), value: PHash::from_values(0, 0, 0, 0), index: 18446744073709551615, siblings: vec![PHash::from_values(0, 0, 0, 0)] }, "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffff010000000000000000000000000000000000000000000000000000000000000000000000"),
            (MerkleProofCore { root: PHash::from_values(0, 0, 0, 0), value: PHash::from_values(0, 0, 0, 0), index: 18446744073709551615, siblings: vec![PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0)] }, "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffff7f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
            (MerkleProofCore { root: PHash::from_values(0, 0, 0, 0), value: PHash::from_values(0, 0, 0, 0), index: 0, siblings: vec![PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0)] }, "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
            (MerkleProofCore { root: PHash::from_values(0, 0, 0, 0), value: PHash::from_values(0, 0, 0, 0), index: 18446744073709551615, siblings: vec![PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0), PHash::from_values(0, 0, 0, 0)] }, "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffff03000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
            (MerkleProofCore { root: PHash::from_values(16800782740852329776, 17399619123754699435, 12125480506524328318, 16555781485258798203), value: PHash::from_values(6110882645125703240, 5095856336231713840, 18342517363125292349, 12063996829202185669), index: 18446744073709551615, siblings: vec![] }, "304d0471e35e28e9ab0a7eea67dd77f17e614ef2465c46a87bf4d6678bf3c1e54826d18e6337ce5430cc83bb561eb8463d8d84e35bb68dfec5fd08c832ed6ba7ffffffffffffffff00000000"),
            (MerkleProofCore { root: PHash::from_values(12286464786099311658, 14524674843422923664, 13456103545585243734, 15363045849801781499), value: PHash::from_values(8934107977067256535, 1314584996481859433, 13699698914459446188, 6502482049194170140), index: 1337, siblings: vec![] }, "2a94cb60a04a82aa909b46a8d00292c956967b97e1aebdbafb7079b1cd8034d5d7da13c6de53fc7b69ff5bde16583e12aceb281e941b1fbe1c9792dcf8743d5a390500000000000000000000"),
            (MerkleProofCore { root: PHash::from_values(15497258278849409200, 13614306529645415160, 7014341994850129825, 18116626610239506222), value: PHash::from_values(9963686035986977268, 6373526859116877855, 1958142832920156355, 6563533138411645297), index: 0, siblings: vec![] }, "b0f04cef4b5211d7f8cacb32a8bbefbca1972578e1f257612e07b77fea2f6bfbf41186eca81f468a1f9812f4e8507358c3d8ae2788b82c1b71e987429d5a165b000000000000000000000000"),
            (MerkleProofCore { root: PHash::from_values(473733776468031361, 11845630332664600758, 1365877907049980497, 2898183738011947779), value: PHash::from_values(50635598469419236, 6048813043354977657, 16063788602828932892, 15556429849710568220), index: 18446744073709551615, siblings: vec![PHash::from_values(14261121126346177453, 348786061652560196, 12284966706008387189, 4649328792373896480)] }, "81377b185c0a9306b6d810d7062264a451a24440b892f41203130426c16a3828e450c2fbcee4b3007945ec396ab3f1531c4796ea9f0aeede1c2348dd868ae3d7ffffffffffffffff01000000adbbae121baee9c54489683b1323d704756e216d21f87caa20257149e7bb8540"),
            (MerkleProofCore { root: PHash::from_values(6994784990855667584, 4005291858196669414, 605527238091033549, 6741782402521602140), value: PHash::from_values(11093329501716675777, 5749930873774526611, 4981792585113270083, 13484652468454513088), index: 1337, siblings: vec![PHash::from_values(8892323702957805729, 11574471391394521112, 2753730779528146820, 4392405639847141242), PHash::from_values(8548973760886628343, 2653759009674482022, 2985408177487559063, 10630849499543666831)] }, "809f2fa4e3771261e6a3935db9a79537cd4b3d98d04367085c984727609f8f5dc1fc2e26686cf39993d0614eaadbcb4f43f75924f6e12245c059d3adf91b23bb390500000000000002000000a11096564be1677b18e0fd0268c8a0a084afd5d88d3737267adf8250a8f5f43cf75fc853570ea47666d12353c20bd4249739b188eb4c6e298f80f0904b5d8893"),
            (MerkleProofCore { root: PHash::from_values(15014247731101365138, 13229685353560480911, 10636266898216031931, 18270280572103140077), value: PHash::from_values(4545555984162658155, 17874554495130860395, 4440920845614095942, 7914171658036533108), index: 0, siblings: vec![PHash::from_values(9796874452882377306, 17670926006137144639, 11441113144696002398, 8561220195313652551), PHash::from_values(2059070728964171717, 5525009428585463512, 15179687395253265553, 7436013748325919677), PHash::from_values(5218747492364520880, 10278888568727169178, 12270049547284979225, 14098032322931721083)] }, "92f30236c3525dd08f1c2935bc4899b7bb9669fc639c9b93eda2ed5661138dfd6b97aa8e150f153f6bfba2209c2c0ff8469e74e6fa51a13d7457bb2031c9d46d0000000000000000030000005a4a27a9687df5873f4504f893bd3bf55e57a898c9ffc69e471392896890cf76c5675027eb49931cd83e8573cdc6ac4c91a48bb34215a9d2bd2be33d1b073267b00dd9b631b76c489a68ce80b1f2a58e191e5dc20df947aa7b035200b445a6c3"),
            (MerkleProofCore { root: PHash::from_values(1603887769513482827, 12073038184981106777, 199345262798101135, 16380875449354416404), value: PHash::from_values(0, 0, 0, 0), index: 0, siblings: vec![PHash::from_values(15099475281588297002, 3723922837074311351, 13930556497634282508, 17650215921363548808)] }, "4bda71b96d27421659908677430c8ca78fdabcd87537c40214f1af7c6e8f54e300000000000000000000000000000000000000000000000000000000000000000000000000000000010000002a9ddca5c41c8cd1b778c7121708ae330c4c00cd534753c1887ad199dd29f2f4"),
            (MerkleProofCore { root: PHash::from_values(1, 2, 3, 4), value: PHash::from_values(5, 6, 7, 8), index: 1, siblings: vec![PHash::from_values(9, 10, 11, 12)] }, "0100000000000000020000000000000003000000000000000400000000000000050000000000000006000000000000000700000000000000080000000000000001000000000000000100000009000000000000000a000000000000000b000000000000000c00000000000000"),
            (MerkleProofCore { root: PHash::from_values(1, 2, 3, 4), value: PHash::from_values(5, 6, 7, 8), index: 13376969, siblings: vec![PHash::from_values(9, 10, 11, 12)] }, "01000000000000000200000000000000030000000000000004000000000000000500000000000000060000000000000007000000000000000800000000000000c91dcc00000000000100000009000000000000000a000000000000000b000000000000000c00000000000000"),
            (MerkleProofCore { root: PHash::from_values(15377542273159532984, 1357268484915504263, 13039979631978631809, 9430955774303150070), value: PHash::from_values(14744315035971160984, 11958847450773676705, 2449545420112725809, 13070690152898809751), index: 0, siblings: vec![PHash::from_values(11067589275286287318, 7690272724094952118, 17978177988280137821, 519693131548211929)] }, "b8113a46390168d587a438f47efcd51281526af26250f7b4f61fc2334f7ce182980b830f68549ecca1627352655cf6a5310701d39488fe2197cfba4c716b64b5000000000000000001000000d6b35ca9cef99799b6228e394c56b96a5d382fbca0517ff9d93a245226523607"),
            (MerkleProofCore { root: PHash::from_values(976253043902316143, 16233502923984633033, 9170531450604814737, 16306004526505033536), value: PHash::from_values(13728595884036824801, 18263975543565803154, 4312180521683006759, 5005355057397975249), index: 255, siblings: vec![PHash::from_values(8093372745071932370, 9466657886497423407, 3122344110375183993, 11034501394048194864)] }, "6ffeb094f8588c0dc97c5e8ce6fc48e19101d94ac445447f407f3e54b9904ae2e19ee72438c585be925ea97cfdac76fd2735466a56f1d73bd148e9bae7977645ff0000000000000001000000d233d790a16f51702f40d4f630536083792672ed6ccb542b3099cbf98d6c2299"),
            (MerkleProofCore { root: PHash::from_values(7415944598999604331, 5314485373345290017, 14006607489102825700, 8002706874125157547), value: PHash::from_values(15747790771967073706, 2028432214758221004, 10510357780707455633, 11434771231326629563), index: 65535, siblings: vec![PHash::from_values(13168358511103713288, 2422896383277873003, 17956301955643444781, 8621023636125515933)] }, "6b1c594952baea662157412a4ad8c049e4c84c184d7761c2ab84ce7980530f6faa9d459045648bdacc649f2b5a70261c91b2541db74adc91bb6e14d3d977b09effff00000000000001000000082054014c68bfb66b37db6c6cdb9f212d8ec7f97d9931f99d0082275207a477"),
            (MerkleProofCore { root: PHash::from_values(1156331692391978265, 1128798174440111187, 7389077871121338536, 200865957720292065), value: PHash::from_values(2112678024742281234, 15772287729980521181, 15023238956535387373, 2468706816860118709), index: 16777215, siblings: vec![PHash::from_values(4828864936056365843, 12122744333473595269, 15245820322731640856, 1091737496701502913)] }, "19d58c378c1d0c1053bc9c82f54baa0fa810e3bd2c478b66e1fa6239869ec90212a0895578bd511dddbabd10206ce2daed141a043c447dd0b55e8829c59b4222ffffff00000000000100000013a3fa2d1393034385bf9203bea33ca818c8d9c5ce0894d3c105de0e78a1260f"),
            (MerkleProofCore { root: PHash::from_values(15526299754077845359, 8493053368497094347, 3632784980768939809, 16251497039834310341), value: PHash::from_values(10519736505851022015, 11565147657430797470, 15271883591323613973, 9239116393214746335), index: 4294967295, siblings: vec![PHash::from_values(11182833229156913015, 6746627423552328502, 14828038711764713248, 14460104932693161866)] }, "6f770b4e5d7f78d7cb3eb45f0a63dd75215f1b54b13e6a32c5e6a21f74ea88e1bf8af5b99d9cfd919e8c1a0885a87fa015fbf55f36a1f0d3df9e0da068ef3780ffffffff0000000001000000770f559e9267319b36d3be84e5d5a05d20ff7962a5c6c7cd8ab70cc8d29cacc8"),
            (MerkleProofCore { root: PHash::from_values(5237251156154269527, 14447984540793112792, 1146971946982168893, 13933392710949764948), value: PHash::from_values(6755419468898722814, 17467503325072488631, 7955098312327281430, 11070476784111952757), index: 1099511627775, siblings: vec![PHash::from_values(1260304597558492506, 8829543344647822577, 4471963341864857707, 11609779781764020310)] }, "573f14aa2d74ae48d8084f22648d81c83dd935abe8dcea0f547f2d2cd95a5dc1fe6377183712c05db778e633ba0969f216bb9363c42f666e75a33333fb3ba299ffffffffff000000010000005afd43a65a807d11f1dca51ae4d6887a6b706c48f79a0f3e56788e4433391ea1"),
            (MerkleProofCore { root: PHash::from_values(3033055686197875271, 14670863169496219925, 3168998125000993928, 11282897393763437742), value: PHash::from_values(14026549493740377155, 5571919728177445508, 12983473433512711604, 1855904996363431214), index: 281474976710655, siblings: vec![PHash::from_values(6900233579677198870, 14383406034016540152, 15272057317812803980, 17114239173324924997)] }, "4792cda71394172a15012fb6526099cb882c902e018bfa2bae4c737866e7949c4394d4de7250a8c284fa01b3786f534db4153f634c902eb42e6d1dddc27fc119ffffffffffff00000100000016aae1b7e18dc25ff815c4d5941f9cc78c19a339373ff1d345681b5fdafd81ed"),
            (MerkleProofCore { root: PHash::from_values(13484103533419023889, 1617815470297429988, 17065346094845367887, 6520226235062806062), value: PHash::from_values(10087920889367755195, 1658501022028472912, 15855377450314708600, 6055965798918328961), index: 72057594037927935, siblings: vec![PHash::from_values(2631375816402435443, 69642483973339912, 9509202861619145576, 7717503897562651137)] }, "11ce07c8b82821bbe4b7354399a273164f965b70db49d4ec2ee61914377f7c5abbf901cd997eff8b5022a175e42d04177836bf21c99d09dc811271e8ce1c0b54ffffffffffffff0001000000737d38075d86842408bb815e786bf70068ebefe79e79f783011aeadee7141a6b"),
            (MerkleProofCore { root: PHash::from_values(13814541186733241550, 9335682239447874273, 12682911315416092745, 12678380740370029327), value: PHash::from_values(11584560622681510544, 8307400037169073948, 15265610371777575388, 3080013115165383916), index: 18446744073709551615, siblings: vec![PHash::from_values(8250899323511175836, 6866922859451046471, 4735028803646699646, 15946788945690610484)] }, "cef43c4a041cb7bfe1ba36c288018f81499028f9a4c002b00fdbe8441ca8f2af90d2e83982a0c4a01c8f87be51d04973dc3952a1c057dad3ec1cfa109c67be2affffffffffffffff010000009cfa64373815817247da9649f5354c5f7eb89a129c33b64134cb03700e604edd"),
            (MerkleProofCore { root: PHash::from_values(5685586254749326300, 16013384599777870051, 12213363679096273180, 4239379119002251077), value: PHash::from_values(10070664190109102948, 5600422881168194882, 11413769746729997008, 7040837092874842980), index: 7275676963357187863, siblings: vec![PHash::from_values(14627762030091259426, 17394468305234669207, 16553271202511275355, 16552192308241580362), PHash::from_values(16710808753409801129, 9563066306938752812, 13370775357727688963, 17813754166013833777), PHash::from_values(11195460877022659512, 1076849165069672758, 15377508009862161367, 18026241888780197758), PHash::from_values(1237292238209186520, 18083009809340172466, 11367404183767305631, 10521558488224645581), PHash::from_values(2248167631482022424, 13558952260714396717, 9083518288471456938, 15053725623763780131), PHash::from_values(16572166251266999746, 9044910373524281673, 9502302799557084808, 2328114767404067320), PHash::from_values(15529738804668543030, 17475078715225960871, 6573346552880731919, 5277180881933127419), PHash::from_values(9323961433396136475, 13059949448413147595, 2760132650214600550, 16612170049532792191), PHash::from_values(14498116524232700043, 10703530436500646658, 10042777340898926221, 15606683617567606150), PHash::from_values(7814548914854555115, 15660214335665533746, 1253410008499629905, 10239468874760065845), PHash::from_values(5771616797339732524, 3012048584407263873, 2187610963130976148, 10525727090318767302), PHash::from_values(1287680878219721585, 3381093091110954984, 13927111210778271649, 9525760766603666716), PHash::from_values(15004586155930712105, 15581110403077899044, 12538991921851908473, 11354290790540895623), PHash::from_values(16680494724467479209, 4684730526388489729, 5295732865483270048, 8466054267589960275), PHash::from_values(5390329542563234745, 1084796251132125086, 6615246179345994535, 18305820746765440385), PHash::from_values(2778589849152342011, 16206070749984726327, 14490502282575223539, 11289230463033671883), PHash::from_values(7089691282744788014, 7801423317757847079, 6493323323789812863, 12261365269071743998), PHash::from_values(9015446404613099926, 3043999579804744296, 15115901579691761073, 6991938815485023901), PHash::from_values(8647124797388240093, 12498162656367349654, 15029849637255896731, 5707273016391082368), PHash::from_values(1817459576097153012, 15829708856773155552, 12260273137268686968, 8233577232774348661), PHash::from_values(17464807976763941412, 14317830512662626586, 11009684111506327027, 3838561278953267153), PHash::from_values(9334664259847143589, 10931346912558431300, 6718713964238050801, 6194615322167337783), PHash::from_values(3496279555675260190, 6731324816909765989, 13318311495568659229, 17115873204421678035), PHash::from_values(8254416304006050215, 15774846843755386521, 2319956423267318341, 10757006696322517324), PHash::from_values(11471713759783602418, 4778766476289511530, 15508555106873730198, 15765317389436338618), PHash::from_values(10464557599967187363, 2830215990164558350, 11589109142348740619, 15229555776884058321), PHash::from_values(15799214951108698427, 3343013508285842441, 5161506082592475110, 16921126648901809869), PHash::from_values(11091997018867119356, 2024759790657736341, 7133209137534530091, 12663257708499402118), PHash::from_values(9880465274176353891, 14629778197331091149, 13777324931315609014, 6444522100932668313), PHash::from_values(17597335420165208379, 15487460566967394840, 3819324665443475353, 10959004524139010157), PHash::from_values(1386599480905345118, 6506256351752352718, 10425203344155909454, 18071847363710705971), PHash::from_values(17699535957889318027, 10232771069612106291, 18201916956259257100, 6791915286145918814), PHash::from_values(10279767550141652273, 7751257098191571909, 4343205219774284526, 10777636455473954401), PHash::from_values(4797429860073725536, 958579544276488959, 9182215149494124176, 11346508146772609638), PHash::from_values(5801899827202869236, 18333582302270766952, 8029129486372661043, 12929987230078048070), PHash::from_values(1971787349819775141, 9526728600428219614, 16874261833582338608, 15845877216304290865), PHash::from_values(16169354838573953780, 17799339542665011422, 14004138125159584856, 17897229584672851445), PHash::from_values(230691357125223302, 3047263005530741516, 5289604667081664750, 18249848146441981771), PHash::from_values(8509582584121424476, 14427392156342201644, 11158415930175494678, 10679821935674210783)] }, "dc5b2d3e9342e74ee380787173f83ade1cf930958e957ea9456f56f8d84cd53a6433b367b92fc28b42fdff27f0b2b84dd012f1a51cdb659e64f332320814b66117df6565a665f86427000000224e89ae104000cb97ae4d86c39065f15b4563a87408b9e54a41b1023533b5e5a9bb7a0806b8e8e72c4f978c23d6b68403c9e7b058898eb931b2635d082b37f7b803b8ff59445e9b3661a7389cbcf10ed7e38eba0fe267d57e9f02a07d132afad87ace35bcbe2b11b208a01b9dc1f3fa9f4dbdc7e021c19dcd41200eb3150492186a04ae8c18331f2d7c5c223e132bbcaafc1abfc1230f7e23c2a25eb293e9d0c2857c056729fce54919290f10fa857d88c6cc030df6de83f8e975cb0b204f203630deaa29b784d7a771082b81f383f20f97fedddc37395bfb4e1b6b0d503c491bca04f1855d6581cb713929d4423eb566afff8405f64d267f0dc91ea5488ae68b701c1b2aa833c902eb33e638948a948d5e9f5ac81c5f8b868506fb0f1496d8ebedd1b5d5da726c32f3d287f74154d9512f8a0ac30165113513bec8b0e6198e2cca1cd9e5e61850812ad09f3af2cc2994072c9c94f45b1ec6f4275d05e51292717b59b2efc2de11e82732a8400eec2ea19fcc71db0947c11ca5c394f24c32842978fe719cff3ad024039afd5b393bd879c179efb77203ae87e5adfe508b929da952a92993057de7018ed0cd97810341a0e77db0fb387e495322e15480777d75b983c6e6284cce4a9edf676271f80d0f2793addd5913ce5b8115ee14fb560bfefb473b07bf888f26371db0d17b87e7e0f31ae2510d9b18c9cb00a4104b67ab9c2ec42faba8a4636227e6677d2c39446c7f2440ee28eb1c5afe4b55acbf1e29aa96518936bd4c1d7d683ab3727d753e2ab11d4b356678c6d19d1640cc4e5b0861dd34cc5430c20078960fd4c5b76472ad9bde2b109dc094d080a129ea914e344ff41fe7eadae93819e09ad1f9556caedb78002aec753d25aa753f42aede8a437224626c8552765ff21a4181fdfd26b3c6f3c5981b5e41ca98d11f9448254f4535a540b9e9af638b8144bc9ba719f2b397f195ddd1c0aa3d5d37e3f9a5d0b1f7551e057c57bb478530658dadc341786a5d1d135fe5bd25d4b8d3532ee2fecb87eda731790ce5938d7299563b2ca083ebda45fa3b47132432204c49cde498904895f2c8dc80e2b6339f6a10c88bca9651429664c7acb37439d7ba41a430a3a8c9daa391a88db19339910e9263ab72f246270bb8edfc5cc9d4a0d1282c184a405ad33be1df4a4a1642db09c4b5e012c5642ee647f16e6f5aa147cd36300309ebd3eafc34444f85b0ee99950ea64d4d64191c2bf250cfea3ffe62867d5506cbedbcaf6336dd62d1761e89cd9eac32c26907cbb62d339607e432bf99eb3ecdb48a6f593bb95878544b36f41822f65e5483eed6995fa52d8cf700356d5834298d3416985ea81aa1e1303e13cef3d327aedd4a5a4e9da0d734c3ad9033610eb56d19ccfa8bfc3e732d62a1f533a21f80121b028e0c0bfea808339afc5ee745b7f7ba415e31ddc74f1f12a98ec50b6f4c43ff916beec244d7222a463c613ed3fe40db919560de8b340ae59342ff528e49048f4d0d90bece6c07c86d7f660a75090be5769df4c7d32e277d845068bf3cebf7f76dfe3367db4aba326d6f46972337e18a70b3a5d89dce25325d1bde0c14f42fbd358430629be5bb6b2dea31dc45885fdde7dbf4b271888e1665e0dea01c5502f503f75854a47f6db158c2f58509d27bbb5ff886a3332a919433030c5bd9f58e0d4a2aeea8a64f6b7368494bcf7e85327c44fd5c7a6849461c18762cad0802ba6438c8169a2b2e2ba8da9adf39496477593694"),
            (MerkleProofCore { root: PHash::from_values(8155147606777914509, 2759570565826657920, 11504938342292658272, 15903138040242394609), value: PHash::from_values(4026881702920236425, 12385953677636193994, 1995335611357083114, 819162464268402616), index: 3228080009225448406, siblings: vec![PHash::from_values(5711194938386706604, 16097631232533994499, 9347717487073467811, 18160486510916505609), PHash::from_values(16389394710820380549, 15468285356592161541, 15301746777459305868, 95851282636170814), PHash::from_values(13201078587351844462, 117400877748235976, 8261510465176919694, 4237394974476734063), PHash::from_values(1058706269490834304, 3574459644972341369, 16902609926574346646, 141311586684196293), PHash::from_values(5164071958476325748, 12372294821357544571, 3225848043076165367, 16218461760085537550), PHash::from_values(15931859832635152397, 15994962068392571749, 11926415192181000463, 5407902586921974844), PHash::from_values(9645358845804501559, 12191807433241619524, 6293477622013677596, 3828648470020955796), PHash::from_values(13368235296417573109, 12896652520314108603, 5462415670760329640, 17542151681942751689), PHash::from_values(14111784926581316953, 13629329314512373105, 7963837796292097265, 12544610268429161906), PHash::from_values(13783868262302634375, 10989525641428674487, 13865247455186428441, 914491054717489631), PHash::from_values(15168321248605507268, 1925135989025399476, 6142402017771012711, 13945207150493263522), PHash::from_values(2186784505755859835, 17596532941933236964, 1156605235086015512, 1331836300639679074), PHash::from_values(12064164392234861769, 11753911179265127076, 2073056043987035046, 12949080805058697333), PHash::from_values(18352139552575937127, 7351938805190856591, 13759166938395128841, 2193022202121632600), PHash::from_values(14782396681209190369, 13493977055537397560, 15357612675712922999, 2015451287989946046), PHash::from_values(12242189453679073319, 16827422648915720406, 9070312371372436377, 1975059441746949198), PHash::from_values(10741655785030822514, 12756861445825681358, 7818550815697530046, 18173683721033036522), PHash::from_values(5420893406898313294, 14241220026648610421, 3212177493441960820, 17039491738588171822), PHash::from_values(1255443129127295093, 12035384252280017431, 17600613927132575651, 10950384976054893091), PHash::from_values(1913828333758853545, 13114388924926313725, 916636009974077967, 11481638002869813435), PHash::from_values(8144255164137622631, 617047490036871098, 2314561605348999985, 18095110400759359100), PHash::from_values(6413391639555789347, 11684198432788547347, 6119621064800726200, 8004636845688662263), PHash::from_values(5349549999933579779, 17091195952820081706, 815226613386007916, 8147462969327180940), PHash::from_values(13806132395117101052, 15067124586059702186, 14761374775867245736, 16436844310780305083), PHash::from_values(11319906587301672273, 13857609735126426112, 14756259709966632914, 59446492835314128), PHash::from_values(11791238584465561075, 8927545692815904828, 6744266721652250768, 16896839627192681840), PHash::from_values(10564366958366126370, 8344455126962706949, 2142252047709638257, 17093107306808512543), PHash::from_values(8513222624927333744, 2608779547011259652, 15774127740335469598, 2623074928470540735), PHash::from_values(14638612123872632848, 15478288012540703742, 2090961441480867250, 5930878078760513253), PHash::from_values(16233329022739115658, 16368310834129659634, 4247462131917311877, 127818041153265347), PHash::from_values(10576032131149859708, 9546261825563812436, 2018588742135521011, 11988117810038574936), PHash::from_values(7616855246461348841, 1144412733509431161, 6795700990000429548, 9248716379464141285), PHash::from_values(2429189982468459853, 5091645531441664232, 761425319865253248, 11953523799423781680), PHash::from_values(12524960248186213985, 6392647429239405276, 478056177188936510, 7188824661525870617), PHash::from_values(7468404916995740330, 10446468884845413880, 10413050510229220155, 15861724512905796607), PHash::from_values(11509940361844639077, 7055908717787127121, 14049986771208463437, 15233536076770673729), PHash::from_values(17679786539430616639, 10225290699552225255, 14428256153708434565, 1359810865901232288), PHash::from_values(2629632636367995637, 2652404561528493971, 3182007600388932910, 3279416348708909086), PHash::from_values(6610145829753736883, 2174164249244621510, 4457934797314942688, 1674008098265927912), PHash::from_values(7487607803695717870, 9236308672513771121, 7234302876527316652, 8212338147350303961), PHash::from_values(955790473718878272, 17224856488433668428, 1375828147200463261, 12363837261551321457), PHash::from_values(4592109905345972995, 14973691431690002925, 18418390978507394737, 3281157827229077397), PHash::from_values(18289608203486521240, 5944213801860330049, 3201472837356702513, 4949541432232044778), PHash::from_values(8876053982533027726, 17685292004131755621, 3588262721175426888, 12756919757968206657), PHash::from_values(5103962092881994733, 4839270984335714732, 5881113191649341742, 11811693174254883248), PHash::from_values(17443096015725569950, 10153560687037718056, 7933587861938906736, 2427431562214064700), PHash::from_values(10308266869070418120, 14674245352168542063, 13208280940425874158, 2755182051956659682), PHash::from_values(1316307125895462562, 9286369178998475387, 6778061898796370670, 663682037835005767), PHash::from_values(9782658700331746963, 3092309063324551745, 14244111178811302792, 7197396330230925273), PHash::from_values(18067565231065217729, 16461861062499757699, 5843984282707303797, 7337579880850145325), PHash::from_values(13068876242104803932, 13016439723639699487, 2691219594970054639, 8128836824816319325), PHash::from_values(3172111789031157568, 1278294404192620495, 1028352371816389813, 7893842246906241891)] }, "8de4df608ae72c7180beb80ccff64b266018206f77c0a99ff155a606ca4bb3dc89ad14cf925be237cacef2073fbfe3abea35a0b22adbb01bb83f0dd0eb3f5e0bd62b6c50aa71cc2c34000000ac708c89893d424f031c6c2c514666dfa39db83587c3b98109907367430207fc855f1d9ea7d372e305630dcc9363aad68cad70399fb95ad43e66cbd43b8854016e461f6b08a733b7c8ae80ee7917a1018ede0a29ffc7a6726f0eb6524740ce3a80eb7a2abe47b10e79988bda1b089b31969174a22c2292eac555f5ae230af601748389f71578aa477be46bbb9638b3abf79ef132b483c42c0eb327ad0a8d13e10d58886f1b5619dd65f3629a4185f9dd0f49c5ad6d2383a53c7c6621c0ba0c4b375a5957c432db85446c55fc430032a91cd0fe8d8dec5657941e71997f172235f5e8ce942c8385b9bbfaf748231dfab2a85132871c66ce4bc909382e033e72f3595d978f9f21d7c3710554decc1a25bdf1f4d110483c856eb215702f936817ae8751548d27234abfb727678b58a3829819a2466919416bc0df51b5e2c4ecb00cc40e2476cfb380d2b4e22d72fb74b71a6742e26017323e55a26663bc045487c17bfbe701ec04591ee4d263f27a7133f418bca85655160d106232991e0fa27b12c944139798856ca7a4329751f1471ea3a6e3520d7df9c41c75585a916260b4b3675aaf73b0e5affe8f8fcf1d64550766093457686e61f2be583b01de122e6f1ee1176308769f25cd38ff934aa33c44bb77b5e7455c3321d5be86bea24452f81b2718933b72fee4a9d6f8fb61be0387e9992b7c910b39e07d4eb49b1319d2681b722a485606071295ced7506fe57909b1beecfddb8a12816cea3279540ee535fc4e586e1bd5e13a4b75c6913829faa2c574db1c5469f2932c2e4ec007756f78ec755856d3df3a6c1117127b14364606a7a3b7875b1df141f423ba863b1e95f797a931c6caba488f1afdc48c843eabffb50f1ad632988bb80cbb40ae68eef8569f674c90f2eb340671baaf31456c31900831c3955984f91e207ce6bc9809bf1efb23d22e71b7f10059138789af919c26a2b8ec716fef42ed54f7a846ffcc2e166f03623bbe616b3d4a2a546f822a2030ed6c55511e4944500b8c5c654b679a1171fcbff7ec433c99bfaa9fa462fb2d19d1a884fa4726f0daccbbde7584d0661be45175b8d21063189d00a23422a21e50c0d247f83106c4c8ccd07997304532d300f315f31805e5a2a33c505ce88103e57b901892c6d972985d7045901d1ea27dea227149b6c62b9c92059acc26ba75cd73710e1623e3ceba1d1f90f44988ea36ed70bd9c54df0a2576041de9142d3f34241eb454dc9af5e8dabf41b8f2bf08672410a027002bcc26cbfef3ac9ef0eccdd6b27d81465a96041de5eeab8230b64e528a6e6702bd5e48e1f2e67909fbeb27e385cfda114e04f23ac39ed3cad419c6017c0b4e66309dc59254629a558d227b84f31e971ac477031c580fe2e8a1595ea6e92be6a67d81b469796f435951c5e10fecf9be940b2e4f5ee5094c9a8b0a5a804d4df82c6b37b621e810c957a228a946807d8e514b20910a300bd5269072e3a561160753fc98d1addcfa209af73eb7583e1b07708f65a2061938d10ef1d5c363aad24fe4b31aa567f8c5615e1a50f9903bab69b244968290ff1bdbcc672a20dc6545aeddc685bb9f519d4853989feb614d64d1448794fbc2418403e1596468d33f9e7ea32f385bf5e777ea1fb787e78d8594221287763bc8a060c227c704df12f5027d4cf3547e249317884ae53bcf242e85c6b50dc3282c1e306747cbd3822db34e00309cf4bb5bc65a948fdd2e2c1ee066cf3914c4dd3de89044007f453b17eeddb95ca053e96771060b35cdf52d80ac4eff2023686564d95434c00816f8714050b7315fa6430d4cd12b0cb7fb0aef9d11de1169ec1713714181a37b2c95ab030bb3fda073ba3fed6131ea053dcdcfb14e319802459bff954ffbd7a803892d9867e231c2bdd1fd41f2db80f5167e52314bb55c95ea6d2ceae84475b54db0448e8712dc11142e7b6556548760c76ef5481770f8ee11cc31416bdb49eeae09b1ed634a457bead446ac692f19528b28432e711fd049e99d51b0515e675c90eba39ea75aa8685312f2281e4124a6b1e88c7026386120c4196e3c42570e25f8af21c8d0de141a520e8f6fcfee7a6664a5cbee8aa5eb883d4db7e295688a7a5f3c26a27e505e5b7644127b0a572791cfdf80ee0a5e9f6283105e477ff60c4cdf3509938628d841fcc287414a2e97b516ea2a88e3370aa63fadc5d9471d33d449e263c13ad701dae2bcfa83ee21ec6a4774e4751dbc0bbe001a512d4020850652d4655ce23248b3f95db51ff8d3eff6aea3b4efbfc282f62159255d7b4a14066ecf7040ef0795dd9a052ccf4f45e8fc69bd11b5dc0ba20871450e6363d13fb38f8c6d"),
            (MerkleProofCore { root: PHash::from_values(4253276758181376794, 5990696650843247728, 11178059474264241547, 7676670080054340334), value: PHash::from_values(5582452506846701718, 2825848923779540475, 13801970695054115435, 822083906677865852), index: 8494064565328854040, siblings: vec![PHash::from_values(1264773879965489290, 9394928523317953106, 5683395241619886341, 9266026955801422472), PHash::from_values(12949756714757242762, 8794547222246494170, 15870835918082421995, 5776592043968225910), PHash::from_values(461330971876495365, 5700194253833626147, 7059303376308225968, 10785773669450163413), PHash::from_values(17929054702420917054, 12680593452517043665, 11227084042878169556, 16563296716337830041), PHash::from_values(932562583028963656, 8692332294352377104, 10549400607826116286, 2330277275221112300), PHash::from_values(13226639173447346850, 3534864974838285684, 18297481034948860686, 11792867358146777645), PHash::from_values(15368651029534532489, 13758760908282529037, 10534171466874933243, 1982781457082751800), PHash::from_values(8500575456739136729, 7926820056726258201, 6945943075813076728, 9581078639621009814), PHash::from_values(8125573487058600096, 15129189171526172894, 13617473179293365793, 11662608593386671393), PHash::from_values(12394624807155721364, 16123609477199132956, 17462790438791991840, 16126181252452921157), PHash::from_values(5570876152629534761, 8806979884590250895, 17827826855872382430, 6155213934274094136), PHash::from_values(17413949583364151502, 11083626291222310322, 12436683999525540587, 15688661333253810657), PHash::from_values(6088185064964086254, 12654234739290766585, 10083384159631541730, 14577011454845580828), PHash::from_values(3078767018208054823, 16206402508588334382, 16307911556832228245, 9817831016346678772), PHash::from_values(2132604728338371273, 17893806821936068699, 877978564078138456, 16071908327590144947), PHash::from_values(6243066044264573276, 10649204398420401283, 15809461491324084123, 7962741435885735564), PHash::from_values(2850979896537183425, 8581701842227405658, 9092184392935026945, 15501966985806375449), PHash::from_values(9375009137314517849, 1827193826897596052, 17357276459505557160, 16086771410360981458)] }, "1a73d33eadac063b7054a226dd3a23538bb5b531de71209bee2a82dbc302896a96281656fada784dfba5ccca9f6e37276b420d9f38738abf7c7d1921f5a0680b18bca8fbb7fae075120000008a18898c24618d1152428d2ab77d61820511e63edc79df4e88eabc3b6c8a97808abfd50e1fc7b6b3da8f66661a820c7aeb34d0212e8940dc76e212b9db932a500590951e13fa660623e2791279281b4fb04791da04aff761d5a456c301c4ae953e7b587842ccd0f8d12d6c768f84faafd4b1350f749dce9b99d8b57e9ba6dce548194374ba20f10c109587f22a5ea178befec3aef5ff6692ec35b8e1d5ce5620a26a982140768eb774c53452f75c0e310edb929c0eb6edfd2d52a38561aea8a389e3584caf6a48d50d05b62726f0f0befbcf22fe22e53092381ba6e03a41841bd9145705571cf87519429cefd7b8016ef82eec1f6df264609671b18f42d4f684a0c0750c09d6c370de0081c464adf5d121b63046b5fbfabc210d3b7bb9e8d9a194e4c2b2978d02ac1c7993996491c2df20d248db614b58f2452f05b068b4cbdf29a02d5558ba4f4d8f3b032d8bad387ade4571cd112a69f73824f12476b66b55ce58fb0ce2c6aaf1b26d7c6763f3d099eb12818734fa97ace1e9ff495c52b9d9eed9055c0f947d54f97cd54b73df9cafe285a3187860ef8b1cf6de94aff24bca27ce7a824afab92a2e3d686337b5e8e095f3786d285751e2f4f527d24af13f88c952ed8eb388981d5bf8f5c47f9253f858f44830da342f0cb32ba7a878e30adf5c69b1757dd3a356831c607cfa92c9939bdf96d8767d66db8cce40c42557816ec1f4e05a1cb790275aa347925b54187701313e6d88ed2d7e196ad234d70c22d75953acb323b91a82948e04cc1a7f5b19a81e1425fa6ee1f0d2d779c95db13fdf"),
            (MerkleProofCore { root: PHash::from_values(13446051987299805305, 17325737814222770914, 5776164909361553937, 13672823782526695018), value: PHash::from_values(11377571314543705722, 17922512436009572875, 5003676150680221535, 16846274268315532508), index: 6613475650436209128, siblings: vec![PHash::from_values(1838981586175844903, 10882936844398447143, 11602741959585665831, 10286961347987095574), PHash::from_values(5382733084451685337, 15957527306577077338, 13477053906652094180, 12315281956065819642), PHash::from_values(3499690337361813454, 11434082196915998749, 11385271007323568082, 871397030644823414), PHash::from_values(15932240030869544498, 5662153311706271692, 9303281501928892006, 6573567829845040455), PHash::from_values(1916794882875674346, 10990410443806617369, 3219634775438392815, 14217980744871535470), PHash::from_values(1228325603163101118, 6881406360033370362, 3631184200673753839, 6317256356200180798), PHash::from_values(6753035365632031873, 877452160177021318, 13540311413295316829, 3133261489690706996), PHash::from_values(6372569289991216399, 3622960567638404778, 3330160690710206898, 10264832522492369251), PHash::from_values(11024459782812874894, 15556991449003112755, 742435732759199915, 17498686916940060225), PHash::from_values(10737232282028037930, 15125851938573308795, 6569375583292083765, 14935226783182629999), PHash::from_values(18388736976764489383, 1725033032130084979, 6019724342350863232, 7123408358094712489), PHash::from_values(14595049641852840166, 13242598977915778896, 7620609293503914797, 7169852659173452174), PHash::from_values(6777933186314004703, 7877411215220011808, 16612061846854241553, 17644274673436480682), PHash::from_values(8971859698479606217, 2723648068604686879, 8811089999208649246, 11774268789166601695), PHash::from_values(17877244588616664830, 4268002408747912122, 14246993740743689852, 357837764695987273), PHash::from_values(16279271420450170127, 12623200535081723283, 14684526392512878025, 11925741839836125538), PHash::from_values(10384633978040335311, 8961304783177643072, 3015035499785937680, 13124462832351256212), PHash::from_values(1162529837853331110, 3182971775911164011, 15763023352302725048, 14976828685066728273), PHash::from_values(13618996036953827273, 17168032316212104510, 5964990891160836854, 6706168874581613077), PHash::from_values(12206012341610192982, 5514590267178151699, 1490758742935578921, 2619124953101287778), PHash::from_values(14863030429797385842, 17861310011702275434, 18361582203088784621, 8322782315151396769), PHash::from_values(4475562905379176096, 8550387288286348646, 3987341516060935712, 7228137548870108332), PHash::from_values(13710992553780428119, 9316605496502919482, 10318554374431017035, 10099627666113093619), PHash::from_values(3135892818661099288, 808425401579273194, 11005893168692097720, 1320783016235641025), PHash::from_values(14260027427585075894, 10624500533850263797, 2244454721584515683, 536372539541806366), PHash::from_values(4864634003514090808, 1024682788109473026, 10424428123251013232, 10472784121282577104), PHash::from_values(16362797671115233220, 15054391445864453907, 7771562162286806239, 10226048692439040009), PHash::from_values(8639408033124461264, 4765688902866109059, 927783371251865967, 1506690219486665727), PHash::from_values(15343961833525268197, 14813231792488116926, 11022585107611317868, 4417382202553365332), PHash::from_values(15317747196341389729, 2041550501971063533, 14424652293047118616, 5551118016166316861), PHash::from_values(15881673467774026932, 6433866075818229340, 6503838298690879671, 14575513173289277504), PHash::from_values(10204787745410947292, 4490770690359983825, 17360927697965963182, 18013910067049956472), PHash::from_values(6947009507225396062, 16463783789970734079, 10798726435302746839, 13432178415218210727), PHash::from_values(2372753555688676698, 10624159978956327149, 13406742769843282710, 3776362165077780528), PHash::from_values(17641204445073822701, 5818967304478389563, 17395643909584952354, 9778575405062380508), PHash::from_values(11061910069508169449, 12700650834491732856, 13126826450694131729, 16242909248057620721), PHash::from_values(10786614537291217694, 18170705180733194963, 4921856193376256539, 4845956065738632802), PHash::from_values(13894108380631544703, 2115514167165755653, 4292428101180177136, 1857073309988107360), PHash::from_values(10746683005860943856, 17153699661882165716, 13253327667092519552, 9494797671457670313), PHash::from_values(8006234127305992680, 18173853872453128352, 3363074126575307697, 6661048046557162405)] }, "79a870ce0af999bae2124d10bf6271f0116292b2610f29506a3604dac9a0bfbd7a3e0d62d440e59d0b1adf5e1a8eb9f85f7763ccf2a07045dc3cc00f31fdc9e9e819f27a10c9c75b2800000027e27e6002608519274a615366f5079727939f99563805a116c0f1e4d7a0c28ed9437cab384fb34a5a641fea898674dde4dec9a41f1d08bbfabb149cb0abe8aace5f51d6d16591301dd0cb7f2d05ae9ed23713cfa89b009e7635ea85fbd2170c32de3c3ce5af1addcccf0d087002944e6626ef2f3ce51b81475dd9ec1c013a5bea4e1755cad2991a192fd6a611c88598effd7f18c570ae2c6e636949286a50c5bed70dcda0e30b11fa20e70ca0aa7f5fef7a2babca8e64323eec638a2f67ab5781bc25cce299b75d8621c03a17562d0c5d7fa2a17dd9e8bb34046d61b9947b2b0f5d7d8401ea6f58aaae55e570574732b259c016811b372e63d90836cb02748e8e38242bc3bffe9833b99e634c89e5d7ab40ab875da94d0a41d6fcf709d3d7f22a572349df4f02957bd3d0ab32d2e9d135ce3f76491c2b5b6f2c800ba19544cfa74e2348daea31ff73c0ed31678cf017805b983f655b8a53a9ae4806296edb62e6a8d44552088cca50f79ead9b29c7b72d6357d7c6d7c1698e69ec89016f8063dfe89369520e105e20f3dd90c32f526d110d91383ce689e6aa549a05550eddf4c929855edc72827c1f725ce67c57cc251e12d4ceab47477adf753ebc149b66a3fe4645533cbb18f8ba4beef193fd3a3b7cc63dca527db7c54994ec138d4bf7040fe5190a1b97ebe19325118e019e2eafc91594b8f3eac9cb6219729e04bf80a5cfbb8b3795a11d9040f44fa538f35c7c10e3ee0dd08ed729941e1dde687523b6a64e0a6aba2222106b784751f72f2c2cb8e7300c3982c1da517348a35662d8cfc9e71534bd6400bd3ecd3f746e1a41eef61a15949ce7c75215da37850f19115d56a0b5f18d7764a913effa64a1c2874c29a97ba62d3db01462c1f6a3440059247206e59d6d1744ce6a6da486d21ee0f7edcc3dd9ba71d1fea18f806d6b768073a07e0af9bf641c3e66c552d2ef13a97620c6faa6fbe15537acc410eccd804f6457bd1b6e153b47be3a21826b563b4b814b88839388de328ff3df602ada15298c1847fe65e7ed842beafb88989e1a380bb872ca7386c9bc98c12818cc275d5412b62a897c64cbe5c5f5d017ccf1ce7193634a7e7aade7251f1edda99efb9371073865be2ddaa6824302d5b8189167380e70f6f7a82502ab90d04266ceabcd5691c49769bec95514e313176e2842f1ebd0dfc4f8709c22da6b0940ad181b39ea8dd02a0a24d557e57783025bb5ce2023426f59fb7f0f26e00cffdb0e97c5d6e814e5ce6ce6fdb3f0d4bef2c6d6d42b93cd6cf6ae55c116f8985473537cb5b14d3da1092a0deb9193d4ed72016d5d0b551c18eb98dfd5a82ec83d4bddb36c88094db4c46acddf0967dc5cfe949d1baf4959b7000d4e7946425a4018efb801a046cadc987a1d63b09e8dd17ea456266c523eae578058c267eef0788458a2c343fef95e636e0957bc6860ff3b0acc201c7be4d72ad7927ac8dc95a737c0161aaf68ba5a5d5e9ac9b6ed20ed089d2e3699709316a38b6784510eba30a8af9061556834edd3aac6f925d2f43bf50be7ee1fc150229cff3df8bd69f1dc5b1d94857ab487e9de598699cc839978f3259ea4c641b01150d3a51bdb2bb6f1b86109e7676ae11ebb4e90c5c0b195d3c2f3df16502bfc1b82bf7921f24d44622e80e75d4b40437f335242f5c9d1c005a13833edd05b1df0babfa29dc4913b6034b31356a6c519f097116641e32395d4893952f52e0eee80fae7484b47edb7a9c470352d4cc483e8e9ae1a85db1b6fa0106dcbce7f36fcb10bd48b190aac2ea56bd916e8cb705c"),
            (MerkleProofCore { root: PHash::from_values(2961615415529197127, 11041481073839796459, 1053957698982425829, 4592417878813438777), value: PHash::from_values(15481869486636051008, 6133092133993020340, 12421865502543224642, 12901979316255114352), index: 7237230325421349879, siblings: vec![PHash::from_values(14491802944302492495, 9665981615984376953, 10890497239142179815, 7578888191095642628), PHash::from_values(9119995217248346794, 13538802095482901130, 1541169288592381930, 8603549759684137862), PHash::from_values(3043791433024451024, 33908178061022895, 6465465513366326484, 2574200494445669324), PHash::from_values(3681625173331367649, 15474646232625241745, 10493513497882959602, 11824859004531410531), PHash::from_values(7624237633180447703, 1175370869569494632, 708756956859929129, 8477726791549757446), PHash::from_values(7717082918329071348, 15690624443899333743, 5697219634111613333, 14150491386024769555), PHash::from_values(6097787530988310762, 4483466706882238593, 1651435759907959154, 8401238759164884995), PHash::from_values(1774272992277547582, 16755252195255020553, 2459240605489301112, 1702215455773405756), PHash::from_values(17532599237373261068, 15265265398755404614, 8412004132430207535, 13412414255931780786), PHash::from_values(8572073384765144336, 9603012769433028309, 8493371382768330669, 17231853078439147679), PHash::from_values(4076226809170434876, 2209624701406040010, 16141977706372907655, 10618659603713014570), PHash::from_values(16207972182300058219, 15865666646666484540, 18129534727369254823, 3571111847688235888)] }, "474ef07387c51929eb706b5089383b99e5b42270f168a00e39f3d3a6ba8bbb3f40aae68945a6dad6b47b6525cd1e1d55429fc456dc5463ac70c4d29cd4090db3f79b6cf0a2ce6f640c0000004f2b1c3aff391dc9797c343211772486e72371e689d12297049aa8b6a79e2d69aa62598d54bb907e8a929231c67ce3bbea574a714d55631586d35e41ecf26577d0b1cc7f2eb83d2aafd64eec4e777800d40cbdffa0f2b959ccab1104b665b923e1568dcc96c2173391de76a8c2fcc0d6f29e14e7ed72a09163862c249d561aa4d7b3e280bbbbce69681e081894c14f102912b975b202d60906a8229999efa675f4363d010796186b6f4cae9acc4bc0d995899a721297104f13383b6df1a460c4ea505db473b19f548198012a3779383e72f1b0ee1214eb16033844c9233297743eca45cfe27b9f18096c4234199d86e8780668134dfa20223cb28d34f07b9f170cf5ea5c1d4e50f346abe056001ed9d32fda9e923071bd74b2ee3229b47722ba10bd819f531ff676d586981f3cc14485ade75fd74584de759f38169a13d723ef3c1b87a8afaa9138ca4f3c76f529aa1e87c2a13833d303e02abb1a46a60e5d936b626887d348eee03c9b5157c12b2edca7e7f3b7c70b99fb706ba50e4e238f31")
        ];
        

        for (proof, hex_str) in test_cases.into_iter() {
            check_test_case(&proof, &hex::decode(hex_str).unwrap());
        }

        let fuzz_tests = MerkleProofCore::<Hash>::qp_rand_gen_vec(1337).into_iter();
        for test_case in fuzz_tests.into_iter() {
            let test_ser = test_case.clone().psy_ser_into_bytes_vec().unwrap();
            check_test_case(&test_case, &test_ser);
        }
    }
}
