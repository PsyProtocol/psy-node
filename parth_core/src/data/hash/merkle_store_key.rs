use crate::{data::{hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}, serializable::{QPDSerializable, QPDSerializableFixed}}, protocol::core_types::Q256BitHash, utils::QPGenRandom};

use psy_serialize::FastFixedSerializable;


pub type QMerkleStoreZeroIdKey = SimpleMerkleNodeKey;
pub type QMerkleStoreZeroIdNode<Hash> = SimpleMerkleNode<Hash>;

#[pderive::serialize_copy_default]
pub struct QMerkleStoreSingleIdKey {
    pub tree_id: u64, // 8
    pub level: u8, // 9
    pub index: u64, // 17
}
impl FastFixedSerializable<17> for QMerkleStoreSingleIdKey {
    fn ffs_from_owned_bytes(data: [u8; 17]) -> Self {
        Self {
            tree_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            level: data[8],
            index: u64::from_le_bytes(data[9..17].try_into().unwrap()),
        }
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        Self {
            tree_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            level: data[8],
            index: u64::from_le_bytes(data[9..17].try_into().unwrap()),
        }
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 17 {
            anyhow::bail!("invalid length for QMerkleStoreSingleIdKey, expected 17 bytes, got {}",data.len());
        }
        Ok(Self {
            tree_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            level: data[8],
            index: u64::from_le_bytes(data[9..17].try_into().unwrap()),
        })
    }

    fn ffs_to_bytes(&self) -> [u8; 17] {
        let mut data: [u8; 17] = [0u8; 17];
        data[0..8].copy_from_slice(&self.tree_id.to_le_bytes());
        data[8] = self.level;

        data[9..17].copy_from_slice(&self.index.to_le_bytes());
        data
    }

    fn ffs_into_bytes(self) -> [u8; 17] {
        let mut data: [u8; 17] = [0u8; 17];
        data[0..8].copy_from_slice(&self.tree_id.to_le_bytes());
        data[8] = self.level;

        data[9..17].copy_from_slice(&self.index.to_le_bytes());
        data
    }
}

impl QPDSerializable for QMerkleStoreSingleIdKey {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut data: [u8; 17] = [0u8; 17];
        data[0..8].copy_from_slice(&self.tree_id.to_le_bytes());
        data[8] = self.level;

        data[9..17].copy_from_slice(&self.index.to_le_bytes());
        Ok(data.to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 17 {
            anyhow::bail!("invalid length for QMerkleStoreSingleIdKey, expected 17 bytes, got {}",bytes.len());
        }
        Ok(Self {
            tree_id: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            level: bytes[8],
            index: u64::from_le_bytes(bytes[9..17].try_into().unwrap()),
        })
    }
}


impl QPDSerializableFixed for QMerkleStoreSingleIdKey {
    fn get_fixed_size() -> usize {
        17
    }
}

impl QPGenRandom for QMerkleStoreSingleIdKey {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            tree_id: QPGenRandom::qp_rand_gen(),
            level: QPGenRandom::qp_rand_gen(),
            index: QPGenRandom::qp_rand_gen(),
        }
    }
}

#[pderive::serialize_copy_default]
pub struct QMerkleStoreSingleIdNode<Hash> {
    pub key: QMerkleStoreSingleIdKey,
    pub hash: Hash,
}
impl<Hash: QPGenRandom> QPGenRandom for QMerkleStoreSingleIdNode<Hash> {
    
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            key: QMerkleStoreSingleIdKey::qp_rand_gen(),
            hash: QPGenRandom::qp_rand_gen(),
        }
    }
}
impl<Hash: Q256BitHash> FastFixedSerializable<49> for QMerkleStoreSingleIdNode<Hash> {
    fn ffs_from_owned_bytes(data: [u8; 49]) -> Self {
        Self {
            key: QMerkleStoreSingleIdKey::ffs_from_owned_bytes(data[0..17].try_into().unwrap()),
            hash: Hash::from_ref_32bytes(data[17..49].try_into().unwrap()),
        }
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        Self {
            key: QMerkleStoreSingleIdKey::ffs_from_slice_or_panic(&data[0..17]),
            hash: Hash::from_ref_32bytes(data[17..49].try_into().unwrap()),
        }
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 49 {
            anyhow::bail!("invalid length for QMerkleStoreSingleIdNode, expected 49 bytes, got {}",data.len());
        }
        Ok(Self {
            key: QMerkleStoreSingleIdKey::ffs_try_from_slice(&data[0..17])?,
            hash: Hash::from_slice_32bytes(&data[17..49])?,
        })
    }

    fn ffs_to_bytes(&self) -> [u8; 49] {
        let mut data: [u8; 49] = [0u8; 49];
        data[0..17].copy_from_slice(&self.key.ffs_to_bytes());
        data[17..49].copy_from_slice(&self.hash.into_owned_32bytes());
        data
    }

    fn ffs_into_bytes(self) -> [u8; 49] {
        let mut data: [u8; 49] = [0u8; 49];
        data[0..17].copy_from_slice(&self.key.ffs_into_bytes());
        data[17..49].copy_from_slice(&self.hash.into_owned_32bytes());
        data
    }
}



#[pderive::serialize_copy_default]
pub struct QMerkleStoreDoubleIdKey {
    pub tree_id: u64, // 8
    pub tree_sub_id: u64, // 16
    pub level: u8, // 17
    pub index: u64, // 25
}

impl FastFixedSerializable<25> for QMerkleStoreDoubleIdKey {
    fn ffs_from_owned_bytes(data: [u8; 25]) -> Self {
        Self {
            tree_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            tree_sub_id: u64::from_le_bytes(data[8..16].try_into().unwrap()),
            level: data[16],
            index: u64::from_le_bytes(data[17..25].try_into().unwrap()),
        }
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        Self {
            tree_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            tree_sub_id: u64::from_le_bytes(data[8..16].try_into().unwrap()),
            level: data[16],
            index: u64::from_le_bytes(data[17..25].try_into().unwrap()),
        }
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 25 {
            anyhow::bail!("invalid length for QMerkleStoreDoubleIdKey, expected 25 bytes, got {}",data.len());
        }
        Ok(Self {
            tree_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            tree_sub_id: u64::from_le_bytes(data[8..16].try_into().unwrap()),
            level: data[16],
            index: u64::from_le_bytes(data[17..25].try_into().unwrap()),
        })
    }

    fn ffs_to_bytes(&self) -> [u8; 25] {
        let mut data: [u8; 25] = [0u8; 25];
        data[0..8].copy_from_slice(&self.tree_id.to_le_bytes());
        data[8..16].copy_from_slice(&self.tree_sub_id.to_le_bytes());
        data[16] = self.level;

        data[17..25].copy_from_slice(&self.index.to_le_bytes());
        data
    }

    fn ffs_into_bytes(self) -> [u8; 25] {
        let mut data: [u8; 25] = [0u8; 25];
        data[0..8].copy_from_slice(&self.tree_id.to_le_bytes());
        data[8..16].copy_from_slice(&self.tree_sub_id.to_le_bytes());
        data[16] = self.level;

        data[17..25].copy_from_slice(&self.index.to_le_bytes());
        data
    }
}
impl QPGenRandom for QMerkleStoreDoubleIdKey {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            tree_id: QPGenRandom::qp_rand_gen(),
            tree_sub_id: QPGenRandom::qp_rand_gen(),
            level: QPGenRandom::qp_rand_gen(),
            index: QPGenRandom::qp_rand_gen(),
        }
    }
}
impl QPDSerializable for QMerkleStoreDoubleIdKey {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut data: [u8; 25] = [0u8; 25];
        data[0..8].copy_from_slice(&self.tree_id.to_le_bytes());
        data[8..16].copy_from_slice(&self.tree_sub_id.to_le_bytes());
        data[16] = self.level;

        data[17..25].copy_from_slice(&self.index.to_le_bytes());
        Ok(data.to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 25 {
            anyhow::bail!("invalid length for QMerkleStoreDoubleIdKey, expected 25 bytes, got {}",bytes.len());
        }
        Ok(Self {
            tree_id: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            tree_sub_id: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            level: bytes[16],
            index: u64::from_le_bytes(bytes[17..25].try_into().unwrap()),
        })
    }
}


impl QPDSerializableFixed for QMerkleStoreDoubleIdKey {
    fn get_fixed_size() -> usize {
        25
    }
}





#[pderive::serialize_copy_default]
pub struct QMerkleStoreDoubleIdNode<Hash> {
    pub key: QMerkleStoreDoubleIdKey,
    pub hash: Hash,
}
impl<Hash: Copy> QMerkleStoreDoubleIdNode<Hash> {
    pub fn from_simple_merkle_nodes_for_tree_clone(tree_id: u64, tree_sub_id: u64, nodes: &[SimpleMerkleNode<Hash>] ) -> Vec<Self> {
        let mut result = Vec::with_capacity(nodes.len());
        for node in nodes {
            result.push(Self {
                key: QMerkleStoreDoubleIdKey {
                    tree_id,
                    tree_sub_id,
                    level: node.key.level,
                    index: node.key.index,
                },
                hash: node.value,
            });
        }
        result
    }
    pub fn from_simple_merkle_nodes_for_tree_owned(tree_id: u64, tree_sub_id: u64, nodes: Vec<SimpleMerkleNode<Hash>> ) -> Vec<Self> {
        let mut result = Vec::with_capacity(nodes.len());
        for node in nodes {
            result.push(Self {
                key: QMerkleStoreDoubleIdKey {
                    tree_id,
                    tree_sub_id,
                    level: node.key.level,
                    index: node.key.index,
                },
                hash: node.value,
            });
        }
        result
    }
}



impl<Hash: QPGenRandom> QPGenRandom for QMerkleStoreDoubleIdNode<Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            key: QMerkleStoreDoubleIdKey::qp_rand_gen(),
            hash: QPGenRandom::qp_rand_gen(),
        }
    }
}
impl<Hash: Q256BitHash> FastFixedSerializable<57> for QMerkleStoreDoubleIdNode<Hash> {
    fn ffs_from_owned_bytes(data: [u8; 57]) -> Self {
        Self {
            key: QMerkleStoreDoubleIdKey::ffs_from_owned_bytes(data[0..25].try_into().unwrap()),
            hash: Hash::from_ref_32bytes(data[25..57].try_into().unwrap()),
        }
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        Self {
            key: QMerkleStoreDoubleIdKey::ffs_from_slice_or_panic(&data[0..25]),
            hash: Hash::from_ref_32bytes(data[25..57].try_into().unwrap()),
        }
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 57 {
            anyhow::bail!("invalid length for QMerkleStoreDoubleIdNode, expected 57 bytes, got {}",data.len());
        }
        Ok(Self {
            key: QMerkleStoreDoubleIdKey::ffs_try_from_slice(&data[0..25])?,
            hash: Hash::from_slice_32bytes(&data[25..57])?,
        })
    }

    fn ffs_to_bytes(&self) -> [u8; 57] {
        let mut data: [u8; 57] = [0u8; 57];
        data[0..25].copy_from_slice(&self.key.ffs_to_bytes());
        data[25..57].copy_from_slice(&self.hash.into_owned_32bytes());
        data
    }

    fn ffs_into_bytes(self) -> [u8; 57] {
        let mut data: [u8; 57] = [0u8; 57];
        data[0..25].copy_from_slice(&self.key.ffs_into_bytes());
        data[25..57].copy_from_slice(&self.hash.into_owned_32bytes());
        data
    }
}

pub fn convert_ffs_array_to_vec<const N: usize, T: FastFixedSerializable<N>>(data: &[T]) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::with_capacity(data.len() * N);
    for item in data {
        result.extend_from_slice(&item.ffs_to_bytes());
    }
    result
}
 