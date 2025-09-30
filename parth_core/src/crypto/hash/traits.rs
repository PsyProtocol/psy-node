use crate::{protocol::core_types::QHashBase, utils::math::log2_ceil};


pub trait BasicDataHasher<Data, Hash: PartialEq> {
    fn hash_data(data: Data) -> Hash;
}

pub trait BasicBytesHasher<Hash: PartialEq> {
    fn hash_bytes(data: &[u8]) -> Hash;
}

pub trait CodeSerializableHash {
    fn to_constant_code(&self) -> String;
    fn get_type_name() -> String;
}

pub trait ZeroableHash: Sized + Copy + Clone {
    fn get_zero_value() -> Self;
}

impl<const N: usize> ZeroableHash for [u8; N] {
    fn get_zero_value() -> Self {
       [0u8; N]
    }
}
impl<const N: usize> CodeSerializableHash for [u8; N] {
    fn to_constant_code(&self) -> String {
        let bytes_str = self.iter().map(|b| format!("0x{:02x}", b)).collect::<Vec<_>>().join(", ");
        format!("[{}]", bytes_str)
    }
    fn get_type_name() -> String {
        format!("[u8; {}]", N)
    }
}

pub trait MerkleHasher<Hash: PartialEq> {
    fn two_to_one(left: &Hash, right: &Hash) -> Hash;
    fn two_to_one_swap(swap: bool, left: &Hash, right: &Hash) -> Hash {
        if swap {
            Self::two_to_one(right, left)
        }else{
            Self::two_to_one(left, right)
        }
    }
}

pub trait MerkleLeafHasher<Hash: PartialEq + Copy> {
    fn compute_root_from_leaves(leaves: &[Hash]) -> anyhow::Result<Hash>;
}

impl<Hash: PartialEq + Copy, H: MerkleHasher<Hash>> MerkleLeafHasher<Hash> for H {
    fn compute_root_from_leaves(leaves: &[Hash]) -> anyhow::Result<Hash> {
        let leaves_len = leaves.len();
        if leaves_len == 0 {
            anyhow::bail!("compute_root_from_leaves called with an empty array");
        }else if leaves_len == 1 {
            return Ok(leaves[0]);
        }else if leaves_len == 2{
            return Ok(Self::two_to_one(&leaves[0], &leaves[1]))
        }

        let height = log2_ceil(leaves_len);
        if leaves_len != (1usize<<height) {
            anyhow::bail!("compute_root_from_leaves called where leaves.len() is not a power of 2");
        }else{
            let mut current_leaves_len = leaves_len>>1;
            let mut current_leaves = Vec::with_capacity(current_leaves_len);
            for i in 0..current_leaves_len {
                current_leaves.push(Self::two_to_one(&leaves[i*2], &leaves[i*2+1]));
            }

            while current_leaves_len > 1 {
                let level_leaves_len = current_leaves_len >> 1;
                let mut level_leaves = Vec::with_capacity(level_leaves_len);

                for i in 0..level_leaves_len {
                    level_leaves.push(Self::two_to_one(&current_leaves[i*2], &current_leaves[i*2+1]));
                }

                current_leaves = level_leaves;
                current_leaves_len = level_leaves_len;
            }

            Ok(current_leaves[0])
        }
    }
}
pub trait MerkleZeroHasher<Hash: PartialEq>: MerkleHasher<Hash> {
    fn get_zero_hash(reverse_level: usize) -> Hash;
}



pub trait QHashable<Hash: QHashBase, QH: QHasher<Hash>> {
    fn get_q_hash(&self) -> Hash;
}
pub trait QHasher<Hash: QHashBase>: MerkleHasher<Hash> + MerkleZeroHasher<Hash> + Sized {
    fn q_hash<T: QHashable<Hash, Self>>(target: &T) -> Hash;
}


pub trait QParthJunctionBase<Hash: PartialEq + Copy>{
    fn get_state_hash(&self) -> Hash;
    fn with_state_hash(&self, state_hash: Hash) -> Self;
}
pub trait QParthJunction<Hash: QHashBase, QH: QHasher<Hash>>: QParthJunctionBase<Hash> + QHashable<Hash, QH> + PartialEq + Clone{
}