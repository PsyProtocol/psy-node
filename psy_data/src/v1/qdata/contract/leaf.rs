use parth_core::{crypto::hash::traits::{FieldQHasher, QFieldHashable}, data::serializable::{FastFixedSerializable, QPDSerializable}, felt::{QFelt, QFelt64, QFeltSized, ToQFelts}, impl_qpd_serialize_params, protocol::core_types::{Q256BitHash, QFHashBase, QHashBase}, utils::QPGenRandom};
use pser::{QBytesDeserialize, QBytesSerialize};

use crate::v1::qdata::ffs_sizes::PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF;


#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash), rename = "QEDContractLeaf")]
pub struct PQEDContractLeaf<F, Hash> {
    pub deployer: Hash,
    pub function_tree_root: Hash,
    pub state_tree_height: F,
}
impl_qpd_serialize_params!(
    PQEDContractLeaf,
    { F: QFelt, Hash: QHashBase } => { F, Hash }
);


impl<F: QFelt, Hash: QHashBase> QFeltSized for PQEDContractLeaf<F, Hash> {
    fn q_felt_size() -> usize {
        9
    }
    
    fn self_qsize(&self) -> usize {
        Self::q_felt_size()
    }
}
impl<F: QFelt64, Hash: QFHashBase<F>> ToQFelts<F> for PQEDContractLeaf<F, Hash> {
    fn to_qfelts(&self) -> Vec<F> {
        let deployer = self.deployer.to_4_felts();
        let function_tree_root = self.function_tree_root.to_4_felts();

        vec![
            deployer[0],
            deployer[1],
            deployer[2],
            deployer[3],
            function_tree_root[0],
            function_tree_root[1],
            function_tree_root[2],
            function_tree_root[3],
            self.state_tree_height,
        ]
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != 9 {
            panic!("Invalid number of elements for QEDContractLeaf");
        }
        let deployer = Hash::from_4_felts_slice(&felts[0..4]);
        let function_tree_root = Hash::from_4_felts_slice(&felts[4..8]);
        let state_tree_height = felts[8];
        PQEDContractLeaf {
            deployer,
            function_tree_root,
            state_tree_height,
        }
    }
}


impl<F: QFelt64, Hash: QFHashBase<F>> QFieldHashable<F, Hash> for PQEDContractLeaf<F, Hash> {
    fn qfhash<H: FieldQHasher<F, Hash>>(&self) -> Hash {
        let deployer = self.deployer.to_4_felts();
        let function_tree_root = self.function_tree_root.to_4_felts();

        H::q_hash_many(&[
            deployer[0],
            deployer[1],
            deployer[2],
            deployer[3],
            function_tree_root[0],
            function_tree_root[1],
            function_tree_root[2],
            function_tree_root[3],
            self.state_tree_height,
        ])
    }
}

impl<F: QFelt64, Hash: Q256BitHash>  FastFixedSerializable<72> for PQEDContractLeaf<F, Hash> {
    fn ffs_from_owned_bytes(data: [u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF]) -> Self {
        let deployer = Hash::from_ref_32bytes(&data[0..32].try_into().unwrap());
        let function_tree_root = Hash::from_ref_32bytes(&data[32..64].try_into().unwrap());
        let state_tree_height = F::from_u64_value(
            u64::from_le_bytes(data[64..72].try_into().unwrap())
        );
        PQEDContractLeaf {
            deployer,
            function_tree_root,
            state_tree_height,
        }
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        if data.len() != PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF {
            panic!("Invalid number of bytes for PQEDContractLeaf");
        }
        let deployer = Hash::from_ref_32bytes(&data[0..32].try_into().unwrap());
        let function_tree_root = Hash::from_ref_32bytes(&data[32..64].try_into().unwrap());
        let state_tree_height = F::from_u64_value(
            u64::from_le_bytes(data[64..72].try_into().unwrap())
        );
        PQEDContractLeaf {
            deployer,
            function_tree_root,
            state_tree_height,
        }
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF {
            anyhow::bail!("Invalid number of bytes for PQEDContractLeaf");
        }
        let deployer = Hash::from_ref_32bytes(&data[0..32].try_into().unwrap());
        let function_tree_root = Hash::from_ref_32bytes(&data[32..64].try_into().unwrap());
        let state_tree_height = F::from_u64_value(
            u64::from_le_bytes(data[64..72].try_into().unwrap())
        );
        Ok(PQEDContractLeaf {
            deployer,
            function_tree_root,
            state_tree_height,
        })
    }

    fn ffs_to_bytes(&self) -> [u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF] {
        let mut bytes = [0u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF];
        bytes[0..32].copy_from_slice(&self.deployer.into_owned_32bytes());
        bytes[32..64].copy_from_slice(&self.function_tree_root.into_owned_32bytes());
        bytes[64..72].copy_from_slice(&self.state_tree_height.to_u64_value().to_le_bytes());
        bytes
    }

    fn ffs_into_bytes(self) -> [u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF] {
        let mut bytes = [0u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF];
        bytes[0..32].copy_from_slice(&self.deployer.into_owned_32bytes());
        bytes[32..64].copy_from_slice(&self.function_tree_root.into_owned_32bytes());
        bytes[64..72].copy_from_slice(&self.state_tree_height.to_u64_value().to_le_bytes());
        bytes
    }
}

impl<F: QFelt64 + QPGenRandom, Hash: QPGenRandom> QPGenRandom for PQEDContractLeaf<F, Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        PQEDContractLeaf {
            deployer: Hash::qp_rand_gen(),
            function_tree_root: Hash::qp_rand_gen(),
            state_tree_height: F::qp_rand_gen(),
        }
    }
}


/*
If I want to do high performance serialization, should I do something like this?
*/
impl<F: QFelt64, Hash: Q256BitHash> PQEDContractLeaf<F, Hash> {
    pub fn write_to_buffer(&self, buffer: &mut [u8]) -> anyhow::Result<()> {
        if buffer.len() != PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF {
            anyhow::bail!("Invalid buffer size for PQEDContractLeaf");
        }
        buffer[0..32].copy_from_slice(&self.deployer.into_owned_32bytes());
        buffer[32..64].copy_from_slice(&self.function_tree_root.into_owned_32bytes());
        buffer[64..72].copy_from_slice(&self.state_tree_height.to_u64_value().to_le_bytes());
        Ok(())
    }
}
/*
Or maybe?
*/
impl<F: QFelt64, Hash: Q256BitHash> PQEDContractLeaf<F, Hash> {
    pub fn write_to_vec_buffer(&self, buffer: &mut Vec<u8>) -> anyhow::Result<()> {
        if buffer.len() != PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF {
            anyhow::bail!("Invalid buffer size for PQEDContractLeaf");
        }
        buffer.extend_from_slice(&self.deployer.into_owned_32bytes());
        buffer.extend_from_slice(&self.function_tree_root.into_owned_32bytes());
        buffer.extend_from_slice(&self.state_tree_height.to_u64_value().to_le_bytes());
        Ok(())
    }
}


#[cfg(test)]
mod tests {

}

