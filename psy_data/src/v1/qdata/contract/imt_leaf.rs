#[cfg(all(target_endian = "little", feature = "serialize_bytemuck"))]
use std::fmt::Debug;

use parth_core::{
    crypto::hash::traits::{FieldQHasher, QFieldHashable},
    data::serializable::QPDSerializable,
    felt::{QFelt, QFelt64, QFeltSized, ToQFelts},
    impl_qpd_serialize_params,
    protocol::core_types::{Q256BitHash, QFHashBase, QHashBase},
    utils::QPGenRandom,
};
use pser::{QBytesDeserialize, QBytesSerialize};
use psy_serialize::{
    AutoDatabaseSerializationUseFastFixedSerialize, FastFixedSerializable,
    PsyCanonicalSerializeMetadata,
};

use crate::v1::qdata::ffs_sizes::PSY_OBJECT_FFS_SIZE_IMT_CONTRACT_STATE_LEAF;

/// Leaf preimage for an Indexed Merkle Tree leaf in a contract state tree.
///
/// Each leaf in an IMT stores:
/// - `key`: the 256-bit storage key (e.g., nullifier hash)
/// - `value`: the 256-bit storage value
/// - `next_key`: the key of the successor leaf in sorted order (zero = no successor)
/// - `next_index`: the leaf index of the successor (zero = no successor)
///
/// The leaf hash is computed from all 13 field elements via the field hasher.
/// Index 0 is always the sentinel leaf with all fields set to zero.
#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct IMTContractStateLeaf<F, Hash> {
    pub key: Hash,        // 32 bytes — the storage key
    pub value: Hash,      // 32 bytes — the storage value
    pub next_key: Hash,   // 32 bytes — key of successor in sorted order (0 = no successor)
    pub next_index: F,    // 8 bytes — leaf index of successor (0 = no successor)
}

pser::impl_bytemuck_pod_and_zeroable!(IMTContractStateLeaf, F, Hash);

impl<F: Default, Hash: Default> Default for IMTContractStateLeaf<F, Hash> {
    fn default() -> Self {
        IMTContractStateLeaf {
            key: Hash::default(),
            value: Hash::default(),
            next_key: Hash::default(),
            next_index: F::default(),
        }
    }
}

impl_qpd_serialize_params!(
    IMTContractStateLeaf,
    { F: QFelt, Hash: QHashBase } => { F, Hash }
);

impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for IMTContractStateLeaf<F, Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        IMTContractStateLeaf {
            key: Hash::qp_rand_gen(),
            value: Hash::qp_rand_gen(),
            next_key: Hash::qp_rand_gen(),
            next_index: F::qp_rand_gen(),
        }
    }
}

impl<F: QFelt, Hash: QHashBase> QFeltSized for IMTContractStateLeaf<F, Hash> {
    fn q_felt_size() -> usize {
        13
    }

    fn self_qsize(&self) -> usize {
        Self::q_felt_size()
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> ToQFelts<F> for IMTContractStateLeaf<F, Hash> {
    fn to_qfelts(&self) -> Vec<F> {
        let key = self.key.to_4_felts();
        let value = self.value.to_4_felts();
        let next_key = self.next_key.to_4_felts();

        vec![
            key[0],
            key[1],
            key[2],
            key[3],
            value[0],
            value[1],
            value[2],
            value[3],
            next_key[0],
            next_key[1],
            next_key[2],
            next_key[3],
            self.next_index,
        ]
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != 13 {
            panic!("Invalid number of elements for IMTContractStateLeaf");
        }
        let key = Hash::from_4_felts_slice(&felts[0..4]);
        let value = Hash::from_4_felts_slice(&felts[4..8]);
        let next_key = Hash::from_4_felts_slice(&felts[8..12]);
        let next_index = felts[12];
        IMTContractStateLeaf {
            key,
            value,
            next_key,
            next_index,
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for IMTContractStateLeaf<F, Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        let key = self.key.to_4_felts();
        let value = self.value.to_4_felts();
        let next_key = self.next_key.to_4_felts();

        H::q_hash_many(&[
            key[0],
            key[1],
            key[2],
            key[3],
            value[0],
            value[1],
            value[2],
            value[3],
            next_key[0],
            next_key[1],
            next_key[2],
            next_key[3],
            self.next_index,
        ])
    }
}

pser::impl_bytemuck_ffs!(
    IMTContractStateLeaf,
    { F: QFelt64, Hash: Q256BitHash },
    104
);

pser::impl_bytemuck_ffs_tests!(
    IMTContractStateLeaf,
    { parth_core::PF, parth_core::PHash },
    104
);

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata
    for IMTContractStateLeaf<F, Hash>
{
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 104;
}
impl<F: QFelt64, Hash: Q256BitHash> AutoDatabaseSerializationUseFastFixedSerialize<104>
    for IMTContractStateLeaf<F, Hash>
{
}
psy_serialize::impl_psy_canonical_serialize_for_fixed_type!(
    IMTContractStateLeaf,
    {F: QFelt64, Hash: Q256BitHash} => {F, Hash},
    104
);

// Compile-time size validation
fn _ensure_imt_leaf_compile_time_size_match() {
    let _bytes_h256: [u8; PSY_OBJECT_FFS_SIZE_IMT_CONTRACT_STATE_LEAF] =
        IMTContractStateLeaf::<u64, parth_core::data::hash::hash256::Hash256>::qp_rand_gen()
            .ffs_into_bytes();
    let _bytes_phash: [u8; PSY_OBJECT_FFS_SIZE_IMT_CONTRACT_STATE_LEAF] =
        IMTContractStateLeaf::<parth_core::PF, parth_core::PHash>::qp_rand_gen().ffs_into_bytes();
}

// fallback for big endian platforms, not zero copy
#[cfg(not(all(target_endian = "little", feature = "serialize_bytemuck")))]
impl<F: QFelt64, Hash: Q256BitHash> FastFixedSerializable<104>
    for IMTContractStateLeaf<F, Hash>
{
    fn ffs_from_owned_bytes(data: [u8; PSY_OBJECT_FFS_SIZE_IMT_CONTRACT_STATE_LEAF]) -> Self {
        let key = Hash::from_ref_32bytes(&data[0..32].try_into().unwrap());
        let value = Hash::from_ref_32bytes(&data[32..64].try_into().unwrap());
        let next_key = Hash::from_ref_32bytes(&data[64..96].try_into().unwrap());
        let next_index =
            F::from_u64_value(u64::from_le_bytes(data[96..104].try_into().unwrap()));
        IMTContractStateLeaf {
            key,
            value,
            next_key,
            next_index,
        }
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        if data.len() != PSY_OBJECT_FFS_SIZE_IMT_CONTRACT_STATE_LEAF {
            panic!("Invalid number of bytes for IMTContractStateLeaf");
        }
        let key = Hash::from_ref_32bytes(&data[0..32].try_into().unwrap());
        let value = Hash::from_ref_32bytes(&data[32..64].try_into().unwrap());
        let next_key = Hash::from_ref_32bytes(&data[64..96].try_into().unwrap());
        let next_index =
            F::from_u64_value(u64::from_le_bytes(data[96..104].try_into().unwrap()));
        IMTContractStateLeaf {
            key,
            value,
            next_key,
            next_index,
        }
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != PSY_OBJECT_FFS_SIZE_IMT_CONTRACT_STATE_LEAF {
            anyhow::bail!("Invalid number of bytes for IMTContractStateLeaf");
        }
        let key = Hash::from_ref_32bytes(&data[0..32].try_into().unwrap());
        let value = Hash::from_ref_32bytes(&data[32..64].try_into().unwrap());
        let next_key = Hash::from_ref_32bytes(&data[64..96].try_into().unwrap());
        let next_index =
            F::from_u64_value(u64::from_le_bytes(data[96..104].try_into().unwrap()));
        Ok(IMTContractStateLeaf {
            key,
            value,
            next_key,
            next_index,
        })
    }

    fn ffs_to_bytes(&self) -> [u8; PSY_OBJECT_FFS_SIZE_IMT_CONTRACT_STATE_LEAF] {
        let mut bytes = [0u8; PSY_OBJECT_FFS_SIZE_IMT_CONTRACT_STATE_LEAF];
        bytes[0..32].copy_from_slice(&self.key.into_owned_32bytes());
        bytes[32..64].copy_from_slice(&self.value.into_owned_32bytes());
        bytes[64..96].copy_from_slice(&self.next_key.into_owned_32bytes());
        bytes[96..104].copy_from_slice(&self.next_index.to_u64_value().to_le_bytes());
        bytes
    }

    fn ffs_into_bytes(self) -> [u8; PSY_OBJECT_FFS_SIZE_IMT_CONTRACT_STATE_LEAF] {
        let mut bytes = [0u8; PSY_OBJECT_FFS_SIZE_IMT_CONTRACT_STATE_LEAF];
        bytes[0..32].copy_from_slice(&self.key.into_owned_32bytes());
        bytes[32..64].copy_from_slice(&self.value.into_owned_32bytes());
        bytes[64..96].copy_from_slice(&self.next_key.into_owned_32bytes());
        bytes[96..104].copy_from_slice(&self.next_index.to_u64_value().to_le_bytes());
        bytes
    }
}

pser::impl_psy_ser_basic_tests!(
    IMTContractStateLeaf,
    { parth_core::PF, parth_core::PHash },
    imt_contract_state_leaf_tests
);
