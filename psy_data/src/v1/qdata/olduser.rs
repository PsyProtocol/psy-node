use parth_core::{crypto::hash::traits::{FieldQHasher, QFieldHashable}, data::serializable::{FastFixedSerializable, QPDSerializable}, felt::{QFelt, QFelt64, QFeltSized, ToQFelts, ZeroableFelt}, impl_qpd_serialize_params, protocol::core_types::{Q256BitHash, QFHashBase, QHashBase}};
use pser::{QBytesDeserialize, QBytesSerialize};

use crate::v1::qdata::ffs_sizes::PSY_OBJECT_FFS_SIZE_USER_LEAF;

#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash), rename = "QEDUserLeaf")]
#[repr(C)]
pub struct PQEDUserLeaf<F, Hash> {
    pub public_key: Hash,
    pub user_state_tree_root: Hash,
    pub balance: F,
    pub nonce: F,
    pub last_checkpoint_id: F,
    pub event_index: F,
    pub user_id: F,
}
impl<F: ZeroableFelt, Hash> PQEDUserLeaf<F, Hash> {
    pub fn new_user_default(user_id: F, public_key: Hash, user_state_tree_root: Hash) -> Self {
        Self {
            public_key,
            user_state_tree_root,
            balance: F::ZERO_VALUE,
            nonce: F::ZERO_VALUE,
            last_checkpoint_id: F::ZERO_VALUE,
            event_index: F::ZERO_VALUE,
            user_id,
        }
    }

}


impl_qpd_serialize_params!(
    PQEDUserLeaf,
    { F: QFelt, Hash: QHashBase } => { F, Hash }
);

impl<F: QFelt, Hash: QHashBase> QFeltSized for PQEDUserLeaf<F, Hash> {
    fn q_felt_size() -> usize {
        13
    }
}
impl<F: QFelt64, Hash: QFHashBase<F>> ToQFelts<F> for PQEDUserLeaf<F, Hash> {
    fn to_qfelts(&self) -> Vec<F> {
        let public_key_felts = self.public_key.to_4_felts();
        let user_state_tree_root_felts = self.user_state_tree_root.to_4_felts();

        vec![
            public_key_felts[0],
            public_key_felts[1],
            public_key_felts[2],
            public_key_felts[3],
            user_state_tree_root_felts[0],
            user_state_tree_root_felts[1],
            user_state_tree_root_felts[2],
            user_state_tree_root_felts[3],
            self.balance,
            self.nonce,
            self.last_checkpoint_id,
            self.event_index,
            self.user_id,
        ]
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != 13 {
            panic!("Invalid number of elements for QEDUserLeaf");
        }
        let public_key = Hash::from_4_felts_slice(&felts[0..4]);
        let user_state_tree_root = Hash::from_4_felts_slice(&felts[4..8]);
        let balance = felts[8];
        let nonce = felts[9];
        let last_checkpoint_id = felts[10];
        let event_index = felts[11];
        let user_id = felts[12];
        PQEDUserLeaf {
            public_key,
            user_state_tree_root,
            balance,
            nonce,
            last_checkpoint_id,
            event_index,
            user_id,
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for PQEDUserLeaf<F, Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        let public_key_felts = self.public_key.to_4_felts();
        let user_state_tree_root_felts = self.user_state_tree_root.to_4_felts();
        H::q_hash_many(&[
            public_key_felts[0],
            public_key_felts[1],
            public_key_felts[2],
            public_key_felts[3],
            user_state_tree_root_felts[0],
            user_state_tree_root_felts[1],
            user_state_tree_root_felts[2],
            user_state_tree_root_felts[3],
            self.balance,
            self.nonce,
            self.last_checkpoint_id,
            self.event_index,
            self.user_id,
        ])
    }
}



#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serialize_bytemuck", derive(bytemuck::Pod, bytemuck::Zeroable))]
#[repr(C)]
struct PQEDUserLeafSerialize256HashU64Felt {
    pub public_key: [u8; 32],
    pub user_state_tree_root: [u8; 32],
    pub balance: u64,
    pub nonce: u64,
    pub last_checkpoint_id: u64,
    pub event_index: u64,
    pub user_id: u64,
}

#[cfg(all(target_endian = "little", feature = "serialize_bytemuck"))]
impl FastFixedSerializable<104> for PQEDUserLeafSerialize256HashU64Felt {
    #[inline(always)]
    fn ffs_from_owned_bytes(data: [u8; 104]) -> Self {
        bytemuck::cast(data)
    }
    #[inline(always)]
    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        if data.len() != 104 {
            panic!("Invalid number of bytes for ExampleUserSerialize");
        }
        let mut arr = [0u8; 104];
        arr.copy_from_slice(data);
        Self::ffs_from_owned_bytes(arr)
    }

    #[inline(always)]
    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 104 {
            anyhow::bail!("Invalid number of bytes for ExampleUserSerialize");
        }
        let mut arr = [0u8; 104];
        arr.copy_from_slice(data);
        Ok(Self::ffs_from_owned_bytes(arr))
    }

    #[inline(always)]
    fn ffs_to_bytes(&self) -> [u8; 104] {
        bytemuck::cast(*self)
    }

    #[inline(always)]
    fn ffs_into_bytes(self) -> [u8; 104] {
        bytemuck::cast(self)
    }
}

#[cfg(not(all(target_endian = "little", feature = "serialize_bytemuck")))]
impl FastFixedSerializable<104> for PQEDUserLeafSerialize256HashU64Felt {
    fn ffs_from_owned_bytes(data: [u8; 104]) -> Self {
            let public_key = data[0..32].try_into().unwrap();
            let user_state_tree_root = data[32..64].try_into().unwrap();
            let balance = u64::from_le_bytes(data[64..72].try_into().unwrap());
            let nonce = u64::from_le_bytes(data[72..80].try_into().unwrap());
            let last_checkpoint_id = u64::from_le_bytes(data[80..88].try_into().unwrap());
            let event_index = u64::from_le_bytes(data[88..96].try_into().unwrap());
            let user_id = u64::from_le_bytes(data[96..104].try_into().unwrap());
            return PQEDUserLeafSerialize256HashU64Felt {
                public_key,
                user_state_tree_root,
                balance,
                nonce,
                last_checkpoint_id,
                event_index,
                user_id,
            }
    }
    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        if data.len() != 104 {
            panic!("Invalid number of bytes for ExampleUserSerialize");
        }
        let mut arr = [0u8; 104];
        arr.copy_from_slice(data);
        Self::ffs_from_owned_bytes(arr)
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 104 {
            anyhow::bail!("Invalid number of bytes for ExampleUserSerialize");
        }
        let mut arr = [0u8; 104];
        arr.copy_from_slice(data);
        Ok(Self::ffs_from_owned_bytes(arr))
    }

    fn ffs_to_bytes(&self) -> [u8; 104] {
            let mut bytes = [0u8; 104];
            bytes[0..32].copy_from_slice(&self.public_key);
            bytes[32..64].copy_from_slice(&self.user_state_tree_root);
            bytes[64..72].copy_from_slice(&self.balance.to_le_bytes());
            bytes[72..80].copy_from_slice(&self.nonce.to_le_bytes());
            bytes[80..88].copy_from_slice(&self.last_checkpoint_id.to_le_bytes());
            bytes[88..96].copy_from_slice(&self.event_index.to_le_bytes());
            bytes[96..104].copy_from_slice(&self.user_id.to_le_bytes());
            bytes
    }

    fn ffs_into_bytes(self) -> [u8; 104] {
            let mut bytes = [0u8; 104];
            bytes[0..32].copy_from_slice(&self.public_key);
            bytes[32..64].copy_from_slice(&self.user_state_tree_root);
            bytes[64..72].copy_from_slice(&self.balance.to_le_bytes());
            bytes[72..80].copy_from_slice(&self.nonce.to_le_bytes());
            bytes[80..88].copy_from_slice(&self.last_checkpoint_id.to_le_bytes());
            bytes[88..96].copy_from_slice(&self.event_index.to_le_bytes());
            bytes[96..104].copy_from_slice(&self.user_id.to_le_bytes());
            bytes
    }
}




impl<F: QFelt64, Hash: Q256BitHash> PQEDUserLeaf<F, Hash> {
    #[inline(always)]
    fn to_serialize_h256_u64(self) -> PQEDUserLeafSerialize256HashU64Felt {
        PQEDUserLeafSerialize256HashU64Felt {
            public_key: self.public_key.into_owned_32bytes(),
            user_state_tree_root: self.user_state_tree_root.into_owned_32bytes(),
            balance: self.balance.into_u64_value_serialize_non_canonical(),
            nonce: self.nonce.into_u64_value_serialize_non_canonical(),
            last_checkpoint_id: self.last_checkpoint_id.into_u64_value_serialize_non_canonical(),
            event_index: self.event_index.into_u64_value_serialize_non_canonical(),
            user_id: self.user_id.into_u64_value_serialize_non_canonical(),
        }
    }
    #[inline(always)]
    fn from_serialize_h256_u64(data: PQEDUserLeafSerialize256HashU64Felt) -> Self {
        Self {
            public_key: Hash::from_ref_32bytes(&data.public_key),
            user_state_tree_root: Hash::from_ref_32bytes(&data.user_state_tree_root),
            balance: F::from_u64_value(data.balance),
            nonce: F::from_u64_value(data.nonce),
            last_checkpoint_id: F::from_u64_value(data.last_checkpoint_id),
            event_index: F::from_u64_value(data.event_index),
            user_id: F::from_u64_value(data.user_id),
        }
    }
    #[inline(always)]
    fn to_serialize_bytes(self) -> [u8; 104] {
        let data = self.to_serialize_h256_u64();
        data.ffs_to_bytes()
    }
    #[inline(always)]
    fn from_serialize_bytes(data: [u8; 104]) -> Self {
        let data = PQEDUserLeafSerialize256HashU64Felt::ffs_from_owned_bytes(data);
        Self::from_serialize_h256_u64(data)
    }


}

impl<F: QFelt64, Hash: Q256BitHash> FastFixedSerializable<104> for PQEDUserLeaf<F, Hash> {
    
    #[inline(always)]
    fn ffs_from_owned_bytes(data: [u8; 104]) -> Self {
        Self::from_serialize_bytes(data)
    }

    #[inline(always)]
    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        if data.len() != PSY_OBJECT_FFS_SIZE_USER_LEAF {
            panic!("Invalid number of bytes for PQEDUserLeaf");
        }
        let mut arr = [0u8; PSY_OBJECT_FFS_SIZE_USER_LEAF];
        arr.copy_from_slice(data);
        Self::from_serialize_bytes(arr)
    }

    #[inline(always)]
    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != PSY_OBJECT_FFS_SIZE_USER_LEAF {
            anyhow::bail!("Invalid number of bytes for PQEDUserLeaf");
        }
        let mut arr = [0u8; PSY_OBJECT_FFS_SIZE_USER_LEAF];
        arr.copy_from_slice(data);
        Ok(Self::from_serialize_bytes(arr))
    }

    #[inline(always)]
    fn ffs_to_bytes(&self) -> [u8; PSY_OBJECT_FFS_SIZE_USER_LEAF] {
        self.to_serialize_bytes()
    }

    #[inline(always)]
    fn ffs_into_bytes(self) -> [u8; PSY_OBJECT_FFS_SIZE_USER_LEAF] {
        self.to_serialize_bytes()
    }
}


