use parth_common::memory_stores::simple_memory_merkle_store::SimpleMemoryMerkleStore;
use parth_core::{
    crypto::hash::traits::MerkleZeroHasher, data::queue::queue_key::PCoreQueueItemBase, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase}, utils::{QPGenRandom, math::log2_ceil}
};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{PsyIOReadWrite, PsyCanonicalDatabaseSerializeBaseSingle, FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata};

use rand::RngCore;
use crate::v1::qdata::{
    contract::{PQEDContractLeaf, PQEDContractLeafV2},
    ffs_sizes::PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF,
};

pub const DEPLOY_CONTRACT_QUEUE_MAGIC: [u8; 4] = *b"DCV2";
pub const DEPLOY_CONTRACT_QUEUE_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct PsyDeployContractQueueItemV2<F, Hash> {
    pub rand_key_id: [u8; 16],
    pub contract_leaf: PQEDContractLeafV2<F, Hash>,
    pub function_leaves: Vec<Hash>,
    pub layout_protocol_version: u16,
    pub canonical_layout_verifier_fingerprint: Hash,
    pub canonical_layout_proof: Vec<u8>,
}

impl<F: QFelt64, Hash: Q256BitHash> PsyDeployContractQueueItemV2<F, Hash> {
    pub fn new_from_layout_endpoint<Hasher>(
        deployer: Hash,
        state_tree_height: u16,
        function_leaves: Vec<Hash>,
        code_root: Hash,
        contract_function_tree_height: usize,
        layout_protocol_version: u16,
        state_layout_root: Hash,
        state_layout_field_count: u64,
        state_layout_slot_count: u64,
        canonical_layout_verifier_fingerprint: Hash,
        canonical_layout_proof: Vec<u8>,
    ) -> anyhow::Result<Self>
    where
        Hash: Default + QFHashBase<F>,
        Hasher: MerkleZeroHasher<Hash>,
    {
        anyhow::ensure!(
            log2_ceil(function_leaves.len())
                <= contract_function_tree_height,
            "more leaves than the contract function tree can support"
        );
        anyhow::ensure!(
            state_tree_height < 64,
            "contract state tree height is unsupported"
        );
        anyhow::ensure!(
            state_layout_slot_count <= (1u64 << state_tree_height) * 4,
            "layout slot count exceeds contract state capacity"
        );

        let mut function_tree = SimpleMemoryMerkleStore::<Hasher, Hash>::new(
            contract_function_tree_height as u8,
        );
        for (index, leaf) in function_leaves.iter().enumerate() {
            function_tree.set_leaf(index as u64, *leaf);
        }

        let mut rand_key_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut rand_key_id);
        let value = Self {
            rand_key_id,
            contract_leaf: PQEDContractLeafV2 {
                deployer,
                function_tree_root: function_tree.get_root(),
                code_root,
                state_tree_height: F::from_u16_value(state_tree_height),
                state_layout_root,
                state_layout_field_count:
                    F::from_u64_value(state_layout_field_count),
                state_layout_slot_count:
                    F::from_u64_value(state_layout_slot_count),
            },
            function_leaves,
            layout_protocol_version,
            canonical_layout_verifier_fingerprint,
            canonical_layout_proof,
        };
        value.validate_shape()?;
        Ok(value)
    }

    pub fn validate_shape(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.layout_protocol_version != 0,
            "layout protocol version must be non-zero"
        );
        anyhow::ensure!(
            !self.function_leaves.is_empty(),
            "contracts with no functions are not supported"
        );
        anyhow::ensure!(
            !self.canonical_layout_proof.is_empty(),
            "canonical layout proof is empty"
        );
        anyhow::ensure!(
            self.canonical_layout_proof.len()
                <= psy_core::constants::protocol::
                    STATE_LAYOUT_MAX_PROOF_BYTES,
            "canonical layout proof exceeds maximum size"
        );
        anyhow::ensure!(
            self.contract_leaf.state_layout_field_count.to_u64_value()
                <= self.contract_leaf.state_layout_slot_count.to_u64_value(),
            "layout field count exceeds slot count"
        );
        let state_tree_height =
            self.contract_leaf.state_tree_height.to_u64_value();
        anyhow::ensure!(
            state_tree_height < 64,
            "contract state tree height is unsupported"
        );
        anyhow::ensure!(
            self.contract_leaf.state_layout_slot_count.to_u64_value()
                <= (1u64 << state_tree_height) * 4,
            "layout slot count exceeds contract state capacity"
        );
        Ok(())
    }
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical
    for PsyDeployContractQueueItemV2<F, Hash>
{
    fn fallback_pio_serialized_size(&self) -> usize {
        4 + 2
            + 16
            + PQEDContractLeafV2::<F, Hash>::FIXED_SIZE
            + 4
            + self.function_leaves.len() * 32
            + 2
            + 32
            + 4
            + self.canonical_layout_proof.len()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(
        &self,
        writer: &mut W,
    ) -> anyhow::Result<()> {
        self.validate_shape()?;
        writer.psy_write_bytes_fixed(&DEPLOY_CONTRACT_QUEUE_MAGIC)?;
        writer.psy_write_u16(DEPLOY_CONTRACT_QUEUE_VERSION)?;
        writer.psy_write_bytes_fixed(&self.rand_key_id)?;
        self.contract_leaf.pio_write_to_io(writer)?;
        writer.psy_write_vec_length(self.function_leaves.len())?;
        for leaf in &self.function_leaves {
            writer.psy_write_bytes_fixed(&leaf.into_owned_32bytes())?;
        }
        writer.psy_write_u16(self.layout_protocol_version)?;
        writer.psy_write_bytes_fixed(
            &self
                .canonical_layout_verifier_fingerprint
                .into_owned_32bytes(),
        )?;
        writer.psy_write_bytes_vec(&self.canonical_layout_proof)?;
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(
        reader: &mut R,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            reader.psy_read_bytes_fixed::<4>()?
                == DEPLOY_CONTRACT_QUEUE_MAGIC,
            "invalid deploy queue magic"
        );
        anyhow::ensure!(
            reader.psy_read_u16()? == DEPLOY_CONTRACT_QUEUE_VERSION,
            "unsupported deploy queue version"
        );
        let rand_key_id = reader.psy_read_bytes_16()?;
        let contract_leaf = PQEDContractLeafV2::pio_read_from_io(reader)?;
        let function_leaves_count = reader.psy_read_vec_length()?;
        let mut function_leaves =
            Vec::with_capacity(function_leaves_count);
        for _ in 0..function_leaves_count {
            function_leaves.push(Hash::from_owned_32bytes(
                reader.psy_read_bytes_32()?,
            ));
        }
        let value = Self {
            rand_key_id,
            contract_leaf,
            function_leaves,
            layout_protocol_version: reader.psy_read_u16()?,
            canonical_layout_verifier_fingerprint:
                Hash::from_owned_32bytes(reader.psy_read_bytes_32()?),
            canonical_layout_proof: reader
                .psy_read_bytes_vec_with_max_length(
                    psy_core::constants::protocol::
                        STATE_LAYOUT_MAX_PROOF_BYTES,
                )?,
        };
        value.validate_shape()?;
        Ok(value)
    }
}

impl<F: QFelt64, Hash: Q256BitHash>
    psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for PsyDeployContractQueueItemV2<F, Hash>
{
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata
    for PsyDeployContractQueueItemV2<F, Hash>
{
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> PCoreQueueItemBase
    for PsyDeployContractQueueItemV2<F, Hash>
{
    #[inline]
    fn is_queue_item(data: &[u8]) -> bool {
        data.starts_with(&DEPLOY_CONTRACT_QUEUE_MAGIC)
            && data.len()
                >= 4
                    + 2
                    + 16
                    + PQEDContractLeafV2::<F, Hash>::FIXED_SIZE
                    + 4
                    + 32
                    + 2
                    + 32
                    + 4
                    + 1
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
        0
    }

    #[inline]
    fn has_fixed_size() -> bool {
        false
    }
}

#[pderive::serialize_clone_f_hash]
#[repr(C)]
pub struct PsyDeployContractQueueItem<F, Hash> {
    pub rand_key_id: [u8; 16],
    pub contract_leaf: PQEDContractLeaf<F, Hash>,
    pub function_leaves: Vec<Hash>,
}
impl<F: QFelt64, Hash: Q256BitHash + Default> PsyDeployContractQueueItem<F, Hash> {

    pub fn new_from_leaves_and_deployer<Hasher: MerkleZeroHasher<Hash>>(deployer: Hash, state_tree_height: u16, function_leaves: Vec<Hash>, code_root: Hash, contract_function_tree_height: usize) -> anyhow::Result<Self> {
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
            code_root,
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

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct PsyUpdateContractQueueItem<F, Hash> {
    pub rand_key_id: [u8; 16],
    pub contract_id: u64,
    pub contract_leaf: PQEDContractLeafV2<F, Hash>,
    pub function_leaves: Vec<Hash>,
    pub layout_protocol_version: u16,
    pub canonical_layout_verifier_fingerprint: Hash,
    pub canonical_layout_proof: Vec<u8>,
}
impl<F: QFelt64, Hash: Q256BitHash> PsyUpdateContractQueueItem<F, Hash> {
    pub fn validate_shape(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.contract_id != 0,
            "update contract id must be non-zero"
        );
        anyhow::ensure!(
            self.layout_protocol_version != 0,
            "layout protocol version must be non-zero"
        );
        anyhow::ensure!(
            !self.function_leaves.is_empty(),
            "contracts with no functions are not supported"
        );
        anyhow::ensure!(
            !self.canonical_layout_proof.is_empty(),
            "canonical layout proof is empty"
        );
        anyhow::ensure!(
            self.canonical_layout_proof.len()
                <= psy_core::constants::protocol::
                    STATE_LAYOUT_MAX_PROOF_BYTES,
            "canonical layout proof exceeds maximum size"
        );
        anyhow::ensure!(
            self.contract_leaf.state_layout_field_count.to_u64_value()
                <= self.contract_leaf.state_layout_slot_count.to_u64_value(),
            "layout field count exceeds slot count"
        );
        let state_tree_height =
            self.contract_leaf.state_tree_height.to_u64_value();
        anyhow::ensure!(
            state_tree_height < 64,
            "contract state tree height is unsupported"
        );
        anyhow::ensure!(
            self.contract_leaf.state_layout_slot_count.to_u64_value()
                <= (1u64 << state_tree_height) * 4,
            "layout slot count exceeds contract state capacity"
        );
        Ok(())
    }

    pub fn new_from_leaves_and_deployer<Hasher: MerkleZeroHasher<Hash>>(
        contract_id: u64,
        deployer: Hash,
        state_tree_height: u16,
        state_layout_root: Hash,
        state_layout_field_count: u64,
        state_layout_slot_count: u64,
        layout_protocol_version: u16,
        canonical_layout_verifier_fingerprint: Hash,
        canonical_layout_proof: Vec<u8>,
        function_leaves: Vec<Hash>,
        code_root: Hash,
        contract_function_tree_height: usize,
    ) -> anyhow::Result<Self>
    where
        Hash: Default,
    {
        let m2_height = log2_ceil(function_leaves.len());
        if m2_height > contract_function_tree_height {
            anyhow::bail!("more leaves than the contract function tree can support");
        }

        let mut t = SimpleMemoryMerkleStore::<Hasher, Hash>::new(contract_function_tree_height as u8);
        for (i, l) in function_leaves.iter().enumerate() {
            t.set_leaf(i as u64, *l);
        }
        let function_tree_root = t.get_root();

        let contract_leaf = PQEDContractLeafV2 {
            deployer,
            function_tree_root,
            code_root,
            state_tree_height: F::from_u16_value(state_tree_height),
            state_layout_root,
            state_layout_field_count: F::from_u64_value(state_layout_field_count),
            state_layout_slot_count: F::from_u64_value(state_layout_slot_count),
        };

        let mut rand_key_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut rand_key_id);

        let value = Self {
            rand_key_id,
            contract_id,
            contract_leaf,
            function_leaves,
            layout_protocol_version,
            canonical_layout_verifier_fingerprint,
            canonical_layout_proof,
        };
        value.validate_shape()?;
        Ok(value)
    }
}


impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for PsyUpdateContractQueueItem<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        16 + 8 + PQEDContractLeafV2::<F, Hash>::FIXED_SIZE + 4 + self.function_leaves.len() * 32
            + 2 + 32 + 4 + self.canonical_layout_proof.len()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.validate_shape()?;
        writer.psy_write_bytes_fixed(&self.rand_key_id)?;
        writer.psy_write_u64(self.contract_id)?;
        self.contract_leaf.pio_write_to_io(writer)?;
        writer.psy_write_vec_length(self.function_leaves.len())?;
        for leaf in self.function_leaves.iter() {
            writer.psy_write_bytes_fixed(&leaf.into_owned_32bytes())?;
        }
        writer.psy_write_u16(self.layout_protocol_version)?;
        writer.psy_write_bytes_fixed(
            &self.canonical_layout_verifier_fingerprint.into_owned_32bytes(),
        )?;
        writer.psy_write_bytes_vec(&self.canonical_layout_proof)?;

        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let rand_key_id: [u8; 16] = reader.psy_read_bytes_16()?;
        let contract_id = reader.psy_read_u64()?;
        let contract_leaf = PQEDContractLeafV2::pio_read_from_io(reader)?;

        let function_leaves_count = reader.psy_read_vec_length()?;

        let mut function_leaves = Vec::with_capacity(function_leaves_count);
        for _ in 0..function_leaves_count {
            let function_leaf = Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
            function_leaves.push(function_leaf);
        }
        let layout_protocol_version = reader.psy_read_u16()?;
        let canonical_layout_verifier_fingerprint =
            Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let canonical_layout_proof = reader
            .psy_read_bytes_vec_with_max_length(
                psy_core::constants::protocol::
                    STATE_LAYOUT_MAX_PROOF_BYTES,
            )?;
        let value = Self {
            rand_key_id,
            contract_id,
            contract_leaf,
            function_leaves,
            layout_protocol_version,
            canonical_layout_verifier_fingerprint,
            canonical_layout_proof,
        };
        value.validate_shape()?;
        Ok(value)
    }

}

impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for PsyUpdateContractQueueItem<F, Hash> {}


impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PsyUpdateContractQueueItem<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}


impl<F: QPGenRandom + QFelt64, Hash: QPGenRandom> QPGenRandom
    for PsyUpdateContractQueueItem<F, Hash>
{
    fn qp_rand_gen() -> Self {
        let mut rand_key_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut rand_key_id);
        let state_layout_slot_count = rand::random::<u32>() as u64;
        let function_count =
            (rand::random::<u8>() as usize % 16) + 1;
        Self {
            rand_key_id,
            contract_id: rand::random::<u64>() | 1,
            contract_leaf: PQEDContractLeafV2 {
                deployer: Hash::qp_rand_gen(),
                function_tree_root: Hash::qp_rand_gen(),
                code_root: Hash::qp_rand_gen(),
                state_tree_height: F::from_u16_value(32),
                state_layout_root: Hash::qp_rand_gen(),
                state_layout_field_count:
                    F::from_u64_value(state_layout_slot_count),
                state_layout_slot_count:
                    F::from_u64_value(state_layout_slot_count),
            },
            function_leaves:
                Hash::qp_rand_gen_vec(function_count),
            layout_protocol_version: 1,
            canonical_layout_verifier_fingerprint: Hash::qp_rand_gen(),
            canonical_layout_proof: vec![1],
        }
    }
}

pser::impl_psy_ser_basic_tests_fallback!(
    PsyUpdateContractQueueItem,
    { parth_core::PF, parth_core::PHash },
    psy_update_contract_queue_item
);



impl<F: QFelt64,Hash: Q256BitHash> PCoreQueueItemBase for PsyUpdateContractQueueItem<F, Hash> {

    #[inline]
    fn is_queue_item(data: &[u8]) -> bool {
        data.len() >= (16 + 8 + PQEDContractLeafV2::<F, Hash>::FIXED_SIZE + 4 + 32)
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
    }

    #[inline]
    fn has_fixed_size() -> bool {
        false
    }
}



impl<F: QFelt64,Hash: Q256BitHash> PCoreQueueItemBase for PsyDeployContractQueueItem<F, Hash> {

    #[inline]
    fn is_queue_item(data: &[u8]) -> bool {
        !data.starts_with(&DEPLOY_CONTRACT_QUEUE_MAGIC)
            && data.len()
                >= (16
                    + PQEDContractLeaf::<F, Hash>::FIXED_SIZE
                    + 4
                    + 32)
            && Self::psy_ser_from_slice(data).is_ok()
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

#[cfg(test)]
mod deploy_v2_queue_tests {
    use parth_core::{
        felt::FromPrimitiveValuesFelt, pgoldilocks::QHashOut, PF,
    };

    use super::*;

    fn example_item() -> PsyDeployContractQueueItemV2<PF, QHashOut<PF>> {
        PsyDeployContractQueueItemV2 {
            rand_key_id: [7; 16],
            contract_leaf: PQEDContractLeafV2 {
                deployer: QHashOut::default(),
                function_tree_root: QHashOut::default(),
                code_root: QHashOut::default(),
                state_tree_height: PF::from_u64_value(8),
                state_layout_root: QHashOut::default(),
                state_layout_field_count: PF::from_u64_value(2),
                state_layout_slot_count: PF::from_u64_value(4),
            },
            function_leaves: vec![QHashOut::default()],
            layout_protocol_version: 1,
            canonical_layout_verifier_fingerprint: QHashOut::default(),
            canonical_layout_proof: vec![1, 2, 3],
        }
    }

    #[test]
    fn v2_queue_roundtrip_has_explicit_header() {
        let item = example_item();
        let bytes = item.psy_ser_to_bytes_vec().unwrap();
        assert_eq!(&bytes[..4], &DEPLOY_CONTRACT_QUEUE_MAGIC);
        assert_eq!(
            PsyDeployContractQueueItemV2::psy_ser_from_slice(&bytes)
                .unwrap(),
            item
        );
    }

    #[test]
    fn v2_queue_rejects_wrong_magic() {
        let mut bytes = example_item().psy_ser_to_bytes_vec().unwrap();
        bytes[0] ^= 1;
        assert!(
            PsyDeployContractQueueItemV2::<PF, QHashOut<PF>>::
                psy_ser_from_slice(&bytes)
                .is_err()
        );
    }

    #[test]
    fn v1_queue_discriminator_rejects_v2_item() {
        let bytes = example_item().psy_ser_to_bytes_vec().unwrap();
        assert!(
            !PsyDeployContractQueueItem::<PF, QHashOut<PF>>::
                is_queue_item(&bytes)
        );
        assert!(
            PsyDeployContractQueueItemV2::<PF, QHashOut<PF>>::
                is_queue_item(&bytes)
        );
    }

    #[test]
    fn v2_queue_item_restorable_id_is_random_key() {
        let item = example_item();
        assert_eq!(item.get_restorable_job_id(), item.rand_key_id);
    }
}
