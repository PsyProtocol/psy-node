use pser::{QBytesSerialize, QBytesDeserialize};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializationExamples, PsyCanonicalSerializeMetadata};
use serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
use crate::generic_traits::QNamedType;
use crate::{crypto::hash::traits::MerkleHasher, data::serializable::{QPDSerializable, QPDSerializableFixed}, protocol::core_types::Q256BitHash, utils::{debug_code_string::QToCodeString, QPGenRandom}};



// TagTreeStorageNode size in bytes
// value(32 bytes) + tag(32 bytes) = 64 bytes
pub const PSY_OBJECT_FFS_SIZE_TAG_TREE_STORAGE_NODE: usize = 64;
pub const PSY_OBJECT_FFS_SIZE_TAG_TREE_PROOF_NODE: usize = 64;

/*

Level[0][0] = hash(hash(0,0),Tag[0][0])
Level[0][1] = hash(hash(0,1),Tag[0][1])
Level[0][2] = hash(hash(0,2),Tag[0][2])
Level[0][3] = hash(hash(0,3),Tag[0][3])

Level[1][0] = hash(hash(Level[0][0], Level[0][1]), Tag[1][0])
Level[1][1] = hash(hash(Level[0][2], Level[0][3]), Tag[1][1])
Level[2][0] = hash(hash(Level[1][0], Level[1][1]), Tag[2][0])

Level[n][i] = hash(hash(Level[n-1][2*i], Level[n-1][2*i+1]), Tag[n][i])
*/
#[inline]
pub fn hash_tag_tree_node<Hash, Hasher: MerkleHasher<Hash>>(left: &Hash, right: &Hash, tag: &Hash) -> Hash {
    Hasher::two_to_one(&Hasher::two_to_one(left, right), tag)
}

#[inline]
pub fn hash_tag_tree_node_owned<Hash, Hasher: MerkleHasher<Hash>>(left: Hash, right: Hash, tag: Hash) -> Hash {
    Hasher::two_to_one(&Hasher::two_to_one(&left, &right), &tag)
}

pub fn compute_tag_tree_root_for_proof<Hash: Copy, Hasher: MerkleHasher<Hash>>(
    index: u64,
    leaf: &TagTreeNodePreimage<Hash>,
    siblings: &[TagTreeProofNode<Hash>],
) -> Hash {
    let mut current_value = leaf.get_node_hash::<Hasher>();

    if siblings.len() == 0 {
        return current_value
    }
    for (i, sibling) in siblings.iter().enumerate() {
        let is_right = (index & (1 << i)) != 0;
        current_value = if is_right {
            Hasher::two_to_one(&sibling.sibling, &current_value)
        } else {
            Hasher::two_to_one(&current_value, &sibling.sibling)
        };
        current_value = Hasher::two_to_one(&current_value, &sibling.parent_tag);
    }
    current_value
}

pub fn verify_tag_tree_proof<Hash: PartialEq + Copy, Hasher: MerkleHasher<Hash>>(
    index: u64,
    leaf: &TagTreeNodePreimage<Hash>,
    siblings: &[TagTreeProofNode<Hash>],
    known_root: Hash,
) -> bool {
    if siblings.len() > 64 {
        return false;
    }
    let computed_root = compute_tag_tree_root_for_proof::<Hash, Hasher>(index, leaf, siblings);
    computed_root == known_root
}



#[pderive::serialize_copy_ts_export]
#[repr(C)]
pub struct TagTreeStorageNode<Hash> {
    pub value: Hash,
    pub tag: Hash,
}
#[cfg(feature = "std")]
impl<Hash: QToCodeString> QToCodeString for TagTreeStorageNode<Hash> {
    fn to_debug_code_string(&self) -> String {
        format!(
            "TagTreeStorageNode {{ value: {}, tag: {} }}",
            self.value.to_debug_code_string(),
            self.tag.to_debug_code_string()
        )
    }
}
impl<Hash: QPGenRandom> QPGenRandom for TagTreeStorageNode<Hash> {
    fn qp_rand_gen() -> Self {
        Self {
            value: Hash::qp_rand_gen(),
            tag: Hash::qp_rand_gen(),
        }
    }
}



pser::impl_ffs_psy_serialize_fixed_size_pc!(
    TagTreeStorageNode,
    { Hash: Q256BitHash } => { Hash },
    64,
    { crate::PHash },
    PSY_OBJECT_FFS_SIZE_TAG_TREE_STORAGE_NODE
);
impl<Hash: Default> Default for TagTreeStorageNode<Hash> {
    fn default() -> Self {
        Self {
            value: Default::default(),
            tag: Default::default(),
        }
    }
}
impl<Hash: QPDSerializableFixed + Copy> QPDSerializable for TagTreeStorageNode<Hash> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut result = Vec::with_capacity(Hash::get_fixed_size() * 2);
        result.extend_from_slice(self.value.to_bytes()?.as_slice());
        result.extend_from_slice(self.tag.to_bytes()?.as_slice());
        Ok(result)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != Hash::get_fixed_size() * 2 {
            anyhow::bail!("TagTreeStorageNode: expected {} bytes, got {}", Hash::get_fixed_size() * 2, bytes.len());
        }
        let value = Hash::from_bytes(&bytes[0..Hash::get_fixed_size()])?;
        let tag = Hash::from_bytes(&bytes[Hash::get_fixed_size()..Hash::get_fixed_size() * 2])?;
        Ok(Self { value, tag })
    }
}

#[pderive::serialize_copy_ts_export]
#[repr(C)]
pub struct TagTreeNodePreimage<Hash> {
    pub left: Hash,
    pub right: Hash,
    pub tag: Hash,
}
#[cfg(feature = "std")]
impl<Hash: QToCodeString> QToCodeString for TagTreeNodePreimage<Hash> {
    fn to_debug_code_string(&self) -> String {
        format!(
            "TagTreeNodePreimage {{ left: {}, right: {}, tag: {} }}",
            self.left.to_debug_code_string(),
            self.right.to_debug_code_string(),
            self.tag.to_debug_code_string()
        )
    }
}

impl<Hash: QPGenRandom> QPGenRandom for TagTreeNodePreimage<Hash> {
    fn qp_rand_gen() -> Self {
        Self {
            left: Hash::qp_rand_gen(),
            right: Hash::qp_rand_gen(),
            tag: Hash::qp_rand_gen(),
        }
    }
}

impl<Hash: Default> Default for TagTreeNodePreimage<Hash> {
    fn default() -> Self {
        Self {
            left: Default::default(),
            right: Default::default(),
            tag: Default::default(),
        }
    }
}

impl<Hash> TagTreeNodePreimage<Hash> {
    pub fn get_node_hash<Hasher: MerkleHasher<Hash>>(&self) -> Hash {
        hash_tag_tree_node::<Hash, Hasher>(&self.left, &self.right, &self.tag)
    }
}


#[pderive::serialize_copy_ts_export]
#[repr(C)]
pub struct TagTreeProofNode<Hash> {
    pub sibling: Hash,
    pub parent_tag: Hash,
}

impl<Hash: QPGenRandom> QPGenRandom for TagTreeProofNode<Hash> {
    fn qp_rand_gen() -> Self {
        Self {
            sibling: Hash::qp_rand_gen(),
            parent_tag: Hash::qp_rand_gen(),
        }
    }
}


#[cfg(feature = "std")]
impl<Hash: QToCodeString> QToCodeString for TagTreeProofNode<Hash> {
    fn to_debug_code_string(&self) -> String {
        format!(
            "TagTreeProofNode {{ sibling: {}, parent_tag: {} }}",
            self.sibling.to_debug_code_string(),
            self.parent_tag.to_debug_code_string()
        )
    }
}

pser::impl_ffs_psy_serialize_fixed_size_pc!(
    TagTreeProofNode,
    { Hash: Q256BitHash } => { Hash },
    64,
    { crate::PHash },
    PSY_OBJECT_FFS_SIZE_TAG_TREE_PROOF_NODE
);


#[pderive::serialize_clone_ts_export]
#[repr(C)]
pub struct TagTreeMerkleProofPartial<Hash> {
    pub index: u64,
    pub leaf: TagTreeNodePreimage<Hash>,
    pub siblings: Vec<TagTreeProofNode<Hash>>,
}
impl<Hash: PartialEq + Copy> TagTreeMerkleProofPartial<Hash> {
    pub fn new_from_params(index: u64, leaf: TagTreeNodePreimage<Hash>, siblings: Vec<TagTreeProofNode<Hash>>) -> Self {
        Self {
            index,
            leaf,
            siblings,
        }
    }
}

impl<Hash: PartialEq + Copy> TagTreeMerkleProofPartial<Hash> {
    pub fn get_root<Hasher: MerkleHasher<Hash>>(&self) -> Hash {
        compute_tag_tree_root_for_proof::<Hash, Hasher>(self.index, &self.leaf, &self.siblings)
    }
    pub fn to_proof<Hasher: MerkleHasher<Hash>>(&self) -> TagTreeMerkleProof<Hash> {
        let root = self.get_root::<Hasher>();
        TagTreeMerkleProof {
            index: self.index,
            leaf: self.leaf,
            root,
            siblings: self.siblings.clone(),
        }
    }
}
#[pderive::serialize_clone_ts_export]
#[repr(C)]
pub struct TagTreeMerkleProof<Hash> {
    pub root: Hash,
    pub leaf: TagTreeNodePreimage<Hash>,
    pub index: u64,
    pub siblings: Vec<TagTreeProofNode<Hash>>,
}

#[cfg(feature = "std")]
impl<Hash: QNamedType> QNamedType for TagTreeMerkleProof<Hash> {
    fn q_type_name() -> String {
        format!("TagTreeMerkleProof<{}>", Hash::q_type_name())
    }
}
#[cfg(feature = "rand")]
impl<Hash: QPGenRandom> QPGenRandom for TagTreeMerkleProof<Hash> {
    fn qp_rand_gen() -> Self {
        Self {
            root: Hash::qp_rand_gen(),
            leaf: TagTreeNodePreimage::qp_rand_gen(),
            index: QPGenRandom::qp_rand_gen(),
            siblings: QPGenRandom::qp_rand_gen_vec((u8::qp_rand_gen() % 5) as usize),
        }
    }
}
impl<Hash:  QToCodeString> QToCodeString for TagTreeMerkleProof<Hash> {
    fn to_debug_code_string(&self) -> String {
        format!(
            "TagTreeMerkleProof {{ \nroot: {}, \nleaf: TagTreeNodePreimage \n{{ left: {}, right: {}, tag: {} }},\n index: {}, \nsiblings: {} }}",
            self.root.to_debug_code_string(),
            self.leaf.left.to_debug_code_string(),
            self.leaf.right.to_debug_code_string(),
            self.leaf.tag.to_debug_code_string(),
            self.index,
            TagTreeProofNode::dbg_vec_of_self_to_debug_code_string(&self.siblings),
        )
    }
}
impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for TagTreeMerkleProof<Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}


impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for TagTreeMerkleProof<Hash> {
    
    fn fallback_pio_serialized_size(&self) -> usize {
        32 + 96 + 8 + 4 + (self.siblings.len() * 64)
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.root.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.leaf.left.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.leaf.right.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.leaf.tag.into_owned_32bytes())?;
        writer.psy_write_u64(self.index)?;
        writer.psy_write_vec_length(self.siblings.len())?;
        for sibling in &self.siblings {
            writer.psy_write_bytes_fixed(&sibling.sibling.into_owned_32bytes())?;
            writer.psy_write_bytes_fixed(&sibling.parent_tag.into_owned_32bytes())?;
        }
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let root = Q256BitHash::from_slice_32bytes(&reader.psy_read_bytes_fixed::<32>()?)?;
        let leaf_left = Q256BitHash::from_slice_32bytes(&reader.psy_read_bytes_fixed::<32>()?)?;
        let leaf_right = Q256BitHash::from_slice_32bytes(&reader.psy_read_bytes_fixed::<32>()?)?;
        let leaf_tag = Q256BitHash::from_slice_32bytes(&reader.psy_read_bytes_fixed::<32>()?)?;

        let index = reader.psy_read_u64()?;
        let sibling_count = reader.psy_read_vec_length()?;
        let mut siblings = Vec::with_capacity(sibling_count);
        for _ in 0..sibling_count {
            let sibling_sibling = Q256BitHash::from_slice_32bytes(&reader.psy_read_bytes_fixed::<32>()?)?;
            let sibling_parent_tag = Q256BitHash::from_slice_32bytes(&reader.psy_read_bytes_fixed::<32>()?)?;
            siblings.push(TagTreeProofNode {
                sibling: sibling_sibling,
                parent_tag: sibling_parent_tag,
            });
        }
        Ok(Self {
            root,
            leaf: TagTreeNodePreimage {
                left: leaf_left,
                right: leaf_right,
                tag: leaf_tag,
            },
            index,
            siblings,
        })
    }
}

//#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    TagTreeMerkleProof,
    { Hash: Q256BitHash } => { Hash }
);
//#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for TagTreeMerkleProof<Hash> {}
impl<Hash: Q256BitHash + QPGenRandom> PsyCanonicalSerializationExamples for TagTreeMerkleProof<Hash> {
fn psy_ser_canoical_known_round_trip_serializations() -> Vec<(TagTreeMerkleProof<Hash>, Vec<u8>)> 
{
    vec![        (
            TagTreeMerkleProof { 
root: Hash::from_owned_32bytes(hex_literal::hex!("544f97f8023c4db0ebf6a6f167a25714e9b0a5fdaa5315bd49fbf8716c3a28f1")), 
leaf: TagTreeNodePreimage 
{ left: Hash::from_owned_32bytes(hex_literal::hex!("4ec8e0cfe4e3dba783890f70f5df47049ddf20feb3a1d2c7e77681ed35bdc6c3")), right: Hash::from_owned_32bytes(hex_literal::hex!("22096b9916ef8c540342b77f71abb5e2410ab299066d9c6e7c8b5a64c0ceb454")), tag: Hash::from_owned_32bytes(hex_literal::hex!("79477c2ab382d2c6fb8139e39517418e102836d2d37112d245983864530be1e3")) },
 index: 1651704365918010152, 
siblings: vec![
    TagTreeProofNode { sibling: Hash::from_owned_32bytes(hex_literal::hex!("b68431562efe2c580db47bd3d081d142204f773dd0bc91161ff77d1022549925")), parent_tag: Hash::from_owned_32bytes(hex_literal::hex!("ab0dc2f442e20fe319e08d4cc38070df1d34802ec447d5d45e58492bc958c76b")) },
    TagTreeProofNode { sibling: Hash::from_owned_32bytes(hex_literal::hex!("34a9b599c854d358327d3f991a6e4353795e7205979a5cba5224319c83efe73b")), parent_tag: Hash::from_owned_32bytes(hex_literal::hex!("03a6829615902efa9083ee73fc67170ab48c7c6e910e96510ba4cc812b1ba105")) },
    TagTreeProofNode { sibling: Hash::from_owned_32bytes(hex_literal::hex!("3634356e6fed625976889f70c99792dcd7b8e7c5165c6eac8c2fcb092ebf1774")), parent_tag: Hash::from_owned_32bytes(hex_literal::hex!("f85964bb238e8d81348f22420a7d71ff6b523c05117fd217c3c99fd389b07393")) }
] },
            hex_literal::hex!("544f97f8023c4db0ebf6a6f167a25714e9b0a5fdaa5315bd49fbf8716c3a28f14ec8e0cfe4e3dba783890f70f5df47049ddf20feb3a1d2c7e77681ed35bdc6c322096b9916ef8c540342b77f71abb5e2410ab299066d9c6e7c8b5a64c0ceb45479477c2ab382d2c6fb8139e39517418e102836d2d37112d245983864530be1e3283b81a45e08ec1603000000b68431562efe2c580db47bd3d081d142204f773dd0bc91161ff77d1022549925ab0dc2f442e20fe319e08d4cc38070df1d34802ec447d5d45e58492bc958c76b34a9b599c854d358327d3f991a6e4353795e7205979a5cba5224319c83efe73b03a6829615902efa9083ee73fc67170ab48c7c6e910e96510ba4cc812b1ba1053634356e6fed625976889f70c99792dcd7b8e7c5165c6eac8c2fcb092ebf1774f85964bb238e8d81348f22420a7d71ff6b523c05117fd217c3c99fd389b07393").to_vec(),
            ),
            (
            TagTreeMerkleProof { 
root: Hash::from_owned_32bytes(hex_literal::hex!("071ff44ddaea9fea65d67d7fdce0beb588baf9eecdb02c2f8ec5531893e913c9")), 
leaf: TagTreeNodePreimage 
{ left: Hash::from_owned_32bytes(hex_literal::hex!("af2990aad7c4e0280c76e963e8e8c085bc4179b346b089c0260455e9ed1efd34")), right: Hash::from_owned_32bytes(hex_literal::hex!("73827668ccca6db1c526a20b54ef33318d7120fbe913cf38ccd6b6653e132449")), tag: Hash::from_owned_32bytes(hex_literal::hex!("e9f639822f3f6ff7861dbf256621e002637b818b1e9a79901cd90fc262264c99")) },
 index: 18301030842330890423, 
siblings: vec![
    TagTreeProofNode { sibling: Hash::from_owned_32bytes(hex_literal::hex!("592c0c44edc6c0922c1596ac979be5fbb97c0cf45936889587de60af64ea1ac9")), parent_tag: Hash::from_owned_32bytes(hex_literal::hex!("036f58701446e8a048d0d4f0ce885f59e50d399efd072833759ca754f88bf984")) },
    TagTreeProofNode { sibling: Hash::from_owned_32bytes(hex_literal::hex!("8e15e3b0508b4bb0f1f2d8f4a0992b7a7e5e8b35375d7ede062d18ed811f6e40")), parent_tag: Hash::from_owned_32bytes(hex_literal::hex!("00487e25aa0ae34805c1c72e462dbfe6840f97a4b172a22fed5bfeb60b59402d")) },
    TagTreeProofNode { sibling: Hash::from_owned_32bytes(hex_literal::hex!("ff2525199a4371eeaa1bdedad3cba57a967ddea03666c852394e9438b0d16108")), parent_tag: Hash::from_owned_32bytes(hex_literal::hex!("bfe4bde9bee1c1821a4d52994bbb6ee5a3a64be1f2b68685c65b2bfeec127f44")) }
] },
            hex_literal::hex!("071ff44ddaea9fea65d67d7fdce0beb588baf9eecdb02c2f8ec5531893e913c9af2990aad7c4e0280c76e963e8e8c085bc4179b346b089c0260455e9ed1efd3473827668ccca6db1c526a20b54ef33318d7120fbe913cf38ccd6b6653e132449e9f639822f3f6ff7861dbf256621e002637b818b1e9a79901cd90fc262264c99b7c0998c9652fafd03000000592c0c44edc6c0922c1596ac979be5fbb97c0cf45936889587de60af64ea1ac9036f58701446e8a048d0d4f0ce885f59e50d399efd072833759ca754f88bf9848e15e3b0508b4bb0f1f2d8f4a0992b7a7e5e8b35375d7ede062d18ed811f6e4000487e25aa0ae34805c1c72e462dbfe6840f97a4b172a22fed5bfeb60b59402dff2525199a4371eeaa1bdedad3cba57a967ddea03666c852394e9438b0d16108bfe4bde9bee1c1821a4d52994bbb6ee5a3a64be1f2b68685c65b2bfeec127f44").to_vec(),
            ),
            (
            TagTreeMerkleProof { 
root: Hash::from_owned_32bytes(hex_literal::hex!("376e3bad360bf05b38016acb9296f9fa0d45a2e4699d1a92a075e99e79a1039b")), 
leaf: TagTreeNodePreimage 
{ left: Hash::from_owned_32bytes(hex_literal::hex!("4fe7c1488c469b8b727e5dc67d583e78c599ef903397b3a97b9cb720bcda8427")), right: Hash::from_owned_32bytes(hex_literal::hex!("81b585742c8327e789ab62e3734899e23627cbedbe7e1b8182b1d8c9a3146ba0")), tag: Hash::from_owned_32bytes(hex_literal::hex!("51f9fd51b59e9ea10e1ae2b14351f31078c63db54078cb97ee65be64c69092ca")) },
 index: 11729425331456199639, 
siblings: vec![
    TagTreeProofNode { sibling: Hash::from_owned_32bytes(hex_literal::hex!("aa3472f4d0df7ad39fd8b0700637d22dd58089f52e1e9bebedb8d6f662c4d51b")), parent_tag: Hash::from_owned_32bytes(hex_literal::hex!("f8e85c37389cee363578ea69baaea5f33c1c87b780ea1f05eee28f8c07045719")) },
    TagTreeProofNode { sibling: Hash::from_owned_32bytes(hex_literal::hex!("7b037883233c4503acfb4cbc9547de34f26f2d5807943177099013da1b3e437b")), parent_tag: Hash::from_owned_32bytes(hex_literal::hex!("414201b812bd5907d70263f85c5ed2ff8f136387f7af553329f2dae1b8954d75")) },
    TagTreeProofNode { sibling: Hash::from_owned_32bytes(hex_literal::hex!("aebb29f7be29deb8fb7900e0f9e341586c1c9eed5e4d4a7ef049c44a10843276")), parent_tag: Hash::from_owned_32bytes(hex_literal::hex!("bf88bb07d71e853714eead465dff56dbbb719fdc4ac2f76d1bd2d49c6bc0f778")) }
] },
            hex_literal::hex!("376e3bad360bf05b38016acb9296f9fa0d45a2e4699d1a92a075e99e79a1039b4fe7c1488c469b8b727e5dc67d583e78c599ef903397b3a97b9cb720bcda842781b585742c8327e789ab62e3734899e23627cbedbe7e1b8182b1d8c9a3146ba051f9fd51b59e9ea10e1ae2b14351f31078c63db54078cb97ee65be64c69092cad74bea9c314ac7a203000000aa3472f4d0df7ad39fd8b0700637d22dd58089f52e1e9bebedb8d6f662c4d51bf8e85c37389cee363578ea69baaea5f33c1c87b780ea1f05eee28f8c070457197b037883233c4503acfb4cbc9547de34f26f2d5807943177099013da1b3e437b414201b812bd5907d70263f85c5ed2ff8f136387f7af553329f2dae1b8954d75aebb29f7be29deb8fb7900e0f9e341586c1c9eed5e4d4a7ef049c44a10843276bf88bb07d71e853714eead465dff56dbbb719fdc4ac2f76d1bd2d49c6bc0f778").to_vec(),
            ),
            (
            TagTreeMerkleProof { 
root: Hash::from_owned_32bytes(hex_literal::hex!("f5cf44f73296301157a6823a54936a09d2258c02d91b257d9425e23c56340355")), 
leaf: TagTreeNodePreimage 
{ left: Hash::from_owned_32bytes(hex_literal::hex!("61edc303fe33698adadf3e0b2a59668645aab21af3674cbaf58bfd13f0b88c23")), right: Hash::from_owned_32bytes(hex_literal::hex!("87ab6f7a45a1f06b996f39f82773ff25599c5045de00c8d2d3d9c531e317504b")), tag: Hash::from_owned_32bytes(hex_literal::hex!("1724e1fe2a103c88f944d3be6e0549d63b8e38f31e777f5070ca41541bf5bb87")) },
 index: 18126984087250664759, 
siblings: vec![
    TagTreeProofNode { sibling: Hash::from_owned_32bytes(hex_literal::hex!("1666b20229a437c69d51b67147ff3c51a1f0e251e117bafe073d020abf862f32")), parent_tag: Hash::from_owned_32bytes(hex_literal::hex!("a6f525d69367601263abb804998764414fd8d703492da815e1101fb782e01899")) },
    TagTreeProofNode { sibling: Hash::from_owned_32bytes(hex_literal::hex!("5b759603002b7cecdcb5002b403109094182fca44d6ad2232ec54fcaec13302f")), parent_tag: Hash::from_owned_32bytes(hex_literal::hex!("6327b4c0cdc3cae481049f81eb81f5dc4bcbed6988dc62d12823beffc7eb26dc")) },
    TagTreeProofNode { sibling: Hash::from_owned_32bytes(hex_literal::hex!("461335d2da8239e429e0bc4ccd3800d2d16b2eac4f041b66c384766dadec74dd")), parent_tag: Hash::from_owned_32bytes(hex_literal::hex!("5daa45b67244cd5763024e0188bb66bcab83ec66ba8efdd72efc30d350bba015")) },
    TagTreeProofNode { sibling: Hash::from_owned_32bytes(hex_literal::hex!("f6835a3969b6aea9981159e881a14cdd69b1040d52b272439d290ad5f4d0e38c")), parent_tag: Hash::from_owned_32bytes(hex_literal::hex!("a54d7bb6b11de035f657b650009347293aba2f2543745ef51acedcf35d32b5a2")) }
] },
            hex_literal::hex!("f5cf44f73296301157a6823a54936a09d2258c02d91b257d9425e23c5634035561edc303fe33698adadf3e0b2a59668645aab21af3674cbaf58bfd13f0b88c2387ab6f7a45a1f06b996f39f82773ff25599c5045de00c8d2d3d9c531e317504b1724e1fe2a103c88f944d3be6e0549d63b8e38f31e777f5070ca41541bf5bb8737fdbb89fcfb8ffb040000001666b20229a437c69d51b67147ff3c51a1f0e251e117bafe073d020abf862f32a6f525d69367601263abb804998764414fd8d703492da815e1101fb782e018995b759603002b7cecdcb5002b403109094182fca44d6ad2232ec54fcaec13302f6327b4c0cdc3cae481049f81eb81f5dc4bcbed6988dc62d12823beffc7eb26dc461335d2da8239e429e0bc4ccd3800d2d16b2eac4f041b66c384766dadec74dd5daa45b67244cd5763024e0188bb66bcab83ec66ba8efdd72efc30d350bba015f6835a3969b6aea9981159e881a14cdd69b1040d52b272439d290ad5f4d0e38ca54d7bb6b11de035f657b650009347293aba2f2543745ef51acedcf35d32b5a2").to_vec(),
            ),
            (
            TagTreeMerkleProof { 
root: Hash::from_owned_32bytes(hex_literal::hex!("ffe8ea1ef090bf118fca116ea91f7dc9ca6d4d285706347234fe41c63ca3ee2d")), 
leaf: TagTreeNodePreimage 
{ left: Hash::from_owned_32bytes(hex_literal::hex!("9cf68599e0b88c7990850a82cb323281666eda8f627d16f8455565fab3fbb349")), right: Hash::from_owned_32bytes(hex_literal::hex!("fa2b1b0710ccf5418198b9c2ba80f675098ed1c10246d25df5e6cc2cce7fe168")), tag: Hash::from_owned_32bytes(hex_literal::hex!("53ed29c55f06725ed25026573593046a8b985c84858de34b157e8883c9443df6")) },
 index: 10380596176435272243, 
siblings: vec![TagTreeProofNode { sibling: Hash::from_owned_32bytes(hex_literal::hex!("c3b130aa61f0529cac033aeb8aa605ca3e81e403cb222e5c5f9f3d3c676ed122")), parent_tag: Hash::from_owned_32bytes(hex_literal::hex!("75d4d360a08270fc43be5b782c619e0da93e7083c82df38defb226a51640b9ed")) }] },
            hex_literal::hex!("ffe8ea1ef090bf118fca116ea91f7dc9ca6d4d285706347234fe41c63ca3ee2d9cf68599e0b88c7990850a82cb323281666eda8f627d16f8455565fab3fbb349fa2b1b0710ccf5418198b9c2ba80f675098ed1c10246d25df5e6cc2cce7fe16853ed29c55f06725ed25026573593046a8b985c84858de34b157e8883c9443df633da334539490f9001000000c3b130aa61f0529cac033aeb8aa605ca3e81e403cb222e5c5f9f3d3c676ed12275d4d360a08270fc43be5b782c619e0da93e7083c82df38defb226a51640b9ed").to_vec(),
            )]
}

}
#[cfg(test)]
mod tests_print_psy_ser_gen {
    use super::*;
    use crate::{data::hash::hash256::Hash256, utils::debug_code_string::generate_and_print_psy_ser_canonical_known_round_trip_serializations_replace_hash256_with_generic_hash};
    

    #[test]
    fn print_tag_tree_merkle_proof_psy_ser_canonical_known_round_trip_serializations() {
        generate_and_print_psy_ser_canonical_known_round_trip_serializations_replace_hash256_with_generic_hash::<TagTreeMerkleProof<Hash256>>();
    }

}
pser::impl_psy_ser_basic_tests_fallback!(
    TagTreeMerkleProof,
    { crate::PHash },
    tag_tree_merkle_proof_ser_tests,
    true
);


impl<Hash: PartialEq + Copy> TagTreeMerkleProof<Hash> {
    pub fn new_from_params<Hasher: MerkleHasher<Hash>>(index: u64, leaf: TagTreeNodePreimage<Hash>, siblings: Vec<TagTreeProofNode<Hash>>) -> Self {
        let root = compute_tag_tree_root_for_proof::<Hash, Hasher>(index, &leaf, &siblings);

        Self {
            index,
            leaf,
            root,
            siblings,
        }
    }
    pub fn verify<Hasher: MerkleHasher<Hash>>(&self) -> bool {
        if self.siblings.len() > 64 {
            return false;
        }
        verify_tag_tree_proof::<Hash, Hasher>(self.index, &self.leaf, &self.siblings, self.root)
    }
}

impl<Hash> QPDSerializable for TagTreeMerkleProof<Hash>
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