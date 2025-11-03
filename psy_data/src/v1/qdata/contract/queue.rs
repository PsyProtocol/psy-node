use parth_common::memory_stores::simple_memory_merkle_store::SimpleMemoryMerkleStore;
use parth_core::{
    crypto::hash::traits::MerkleZeroHasher, data::queue::queue_key::PCoreQueueItemBase, felt::QFelt64, protocol::core_types::Q256BitHash, utils::{QPGenRandom, math::log2_ceil}
};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{PsyIOReadWrite, PsyCanonicalDatabaseSerializeBaseSingle, FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata};

use rand::RngCore;
use crate::v1::qdata::{contract::PQEDContractLeaf, ffs_sizes::PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF};

#[pderive::serialize_clone_f_hash]
#[repr(C)]
pub struct PsyDeployContractQueueItem<F, Hash> {
    pub rand_key_id: [u8; 16],
    pub contract_leaf: PQEDContractLeaf<F, Hash>,
    pub function_leaves: Vec<Hash>,
}
impl<F: QFelt64, Hash: Q256BitHash + Default> PsyDeployContractQueueItem<F, Hash> {

    pub fn new_from_leaves_and_deployer<Hasher: MerkleZeroHasher<Hash>>(deployer: Hash, state_tree_height: u16, function_leaves: Vec<Hash>, contract_function_tree_height: usize) -> anyhow::Result<Self> {
        let m2_height = log2_ceil(function_leaves.len());
        if m2_height > contract_function_tree_height {
            anyhow::bail!("more leaves than the contract function tree can support");
        }
        
        // TODO: just hash the leaves properly with the zero hashes

        let mut t = SimpleMemoryMerkleStore::<Hasher, Hash>::new(contract_function_tree_height as u8);
        for (i, l) in function_leaves.iter().enumerate() {
            t.set_leaf(i as u64, *l);
        }
        let function_tree_root = t.get_root();

        let contract_leaf = PQEDContractLeaf {
            deployer,
            function_tree_root,
            state_tree_height: F::from_u16_value(state_tree_height),
        };

        let mut rand_key_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut rand_key_id);

        Ok(Self{
            rand_key_id,
            contract_leaf,
            function_leaves,
        })

        



    }
}


impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for PsyDeployContractQueueItem<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        16 + PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF + self.function_leaves.len() * 32
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.rand_key_id)?;
        self.contract_leaf.pio_write_to_io(writer)?;
        writer.psy_write_vec_length(self.function_leaves.len())?;
        for leaf in self.function_leaves.iter() {
            writer.psy_write_bytes_fixed(&leaf.into_owned_32bytes())?;
        }

        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let rand_key_id: [u8; 16] = reader.psy_read_bytes_16()?;
        let contract_leaf = PQEDContractLeaf::pio_read_from_io(reader)?;

        let function_leaves_count = reader.psy_read_vec_length()?;

        let mut function_leaves = Vec::with_capacity(function_leaves_count);
        for _ in 0..function_leaves_count {
            let function_leaf = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
            function_leaves.push(function_leaf);
        }
        Ok(Self {
            rand_key_id,
            contract_leaf,
            function_leaves,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PsyDeployContractQueueItem,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for PsyDeployContractQueueItem<F, Hash> {}


impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PsyDeployContractQueueItem<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}


impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for PsyDeployContractQueueItem<F, Hash> {
    fn qp_rand_gen() -> Self {
        let mut rand_key_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut rand_key_id);
        Self {
            rand_key_id,
            contract_leaf: PQEDContractLeaf::qp_rand_gen(),
            function_leaves: Hash::qp_rand_gen_vec((rand::random::<u32>()&0xfff) as usize),

        }
    }
}


pser::impl_psy_ser_basic_tests_fallback!(
    PsyDeployContractQueueItem,
    { parth_core::PF, parth_core::PHash },
    psy_deploy_contract_queue_item
);



impl<F: QFelt64,Hash: Q256BitHash> PCoreQueueItemBase for PsyDeployContractQueueItem<F, Hash> {

    #[inline]
    fn is_queue_item(data: &[u8]) -> bool {
        data.len() >= (16 + PQEDContractLeaf::<F, Hash>::FIXED_SIZE + 4 + 32)
    }

    #[inline]
    fn decode_queue_item_ref(data: &[u8]) -> anyhow::Result<Self> {
        Self::psy_ser_from_slice(data)
    }

    #[inline]
    fn encode_queue_item_vec(&self) -> anyhow::Result<Vec<u8>> {
        self.psy_ser_to_bytes_vec()
    }

    #[inline]
    fn get_restorable_job_id(&self) -> Vec<u8> {
        self.rand_key_id.to_vec()
    }

    #[inline]
    fn get_size_hint() -> usize {
        0 // make this 0 since size isn't fixed
        //16 + PQEDContractLeaf::FIXED_SIZE + 4 + 32*16
    }

    #[inline]
    fn has_fixed_size() -> bool {
        false
    }
}