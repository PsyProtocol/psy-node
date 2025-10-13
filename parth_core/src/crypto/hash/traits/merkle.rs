use crate::utils::math::log2_ceil;


pub trait MerkleHasher<Hash> {
    fn two_to_one(left: &Hash, right: &Hash) -> Hash;
    fn two_to_one_swap(swap: bool, left: &Hash, right: &Hash) -> Hash {
        if swap {
            Self::two_to_one(right, left)
        }else{
            Self::two_to_one(left, right)
        }
    }
}

pub trait MerkleLeafHasher<Hash> {
    fn compute_root_from_leaves(leaves: &[Hash]) -> anyhow::Result<Hash>;
}

impl<Hash: Copy, H: MerkleHasher<Hash>> MerkleLeafHasher<Hash> for H {
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
pub trait MerkleZeroHasher<Hash>: MerkleHasher<Hash> {
    fn get_zero_hash(reverse_level: usize) -> Hash;
}