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



#[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
unsafe impl<F, Hash> bytemuck::Zeroable for PQEDUserLeaf<F, Hash>
where
    F: bytemuck::Zeroable,
    Hash: bytemuck::Zeroable,
{
    // The `#[repr(C)]` attribute ensures there are no padding bytes.
    // The trait bounds on F and Hash ensure that all fields are Zeroable.
}

#[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
unsafe impl<F, Hash> bytemuck::Pod for PQEDUserLeaf<F, Hash>
where
    F: bytemuck::Pod,
    Hash: bytemuck::Pod,
{
    // The `#[repr(C)]` attribute ensures a defined layout with no padding.
    // The trait bounds on F and Hash ensure that all fields are Pod.
}

#[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
impl<F: QFelt64 + bytemuck::Pod, Hash: Q256BitHash + bytemuck::Pod> FastFixedSerializable<104> for PQEDUserLeaf<F, Hash> {
    #[inline(always)]
    fn ffs_from_owned_bytes(data: [u8; 104]) -> Self {
        bytemuck::cast(data)
    }

    #[inline(always)]
    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        *bytemuck::from_bytes(data)
    }

    #[inline(always)]
    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        bytemuck::try_from_bytes(data)
            .map(|&s| s)
            .map_err(|e| anyhow::anyhow!("Failed to cast slice to PQEDUserLeaf: {}", e))
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

