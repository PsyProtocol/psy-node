#[cfg(feature = "node")]
use auto_impl::auto_impl;
#[cfg(feature = "rand_gen")]
use parth_core::utils::QPGenRandom;
use parth_core::{crypto::hash::merkle_proof::DeltaMerkleProofCore, protocol::core_types::{Q256BitHash, QHashBase}};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};


#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash))]
pub struct QEDContractStateUpdateHistory<Hash> {
    pub user_contract_tree_update_proof: DeltaMerkleProofCore<Hash>,
    pub contract_state_tree_updates: Vec<DeltaMerkleProofCore<Hash>>,
}
#[cfg(feature = "rand_gen")]
impl<Hash: QPGenRandom> QPGenRandom for QEDContractStateUpdateHistory<Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            user_contract_tree_update_proof: DeltaMerkleProofCore::<Hash>::qp_rand_gen(),
            contract_state_tree_updates: QPGenRandom::qp_rand_gen_vec(rand::random::<u8>() as usize % 5 + 1),
        }
    }
}

impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for QEDContractStateUpdateHistory<Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for QEDContractStateUpdateHistory<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        self.user_contract_tree_update_proof.pio_serialized_size()
        + 4 + self.contract_state_tree_updates.iter().map(|p| p.pio_serialized_size()).sum::<usize>()
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.user_contract_tree_update_proof.pio_write_to_io(writer)?;
        writer.psy_write_vec_length(self.contract_state_tree_updates.len())?;
        for proof in &self.contract_state_tree_updates {
            proof.pio_write_to_io(writer)?;
        }
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let user_contract_tree_update_proof = DeltaMerkleProofCore::pio_read_from_io(reader)?;
        let updates_len = reader.psy_read_vec_length()? as usize;
        let mut contract_state_tree_updates = Vec::with_capacity(updates_len);
        for _ in 0..updates_len {
            contract_state_tree_updates.push(DeltaMerkleProofCore::pio_read_from_io(reader)?);
        }
        Ok(Self {
            user_contract_tree_update_proof,
            contract_state_tree_updates,
        })
    }
}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    QEDContractStateUpdateHistory,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for QEDContractStateUpdateHistory<Hash> {}

pser::impl_psy_ser_basic_tests_fallback!(
    QEDContractStateUpdateHistory,
    { parth_core::PHash },
    qed_contract_state_update_history_ser_tests
);
impl<Hash: QHashBase> QEDContractStateUpdateHistory<Hash> {
    pub fn ensure_basic_consistency<C: PSimpleContractHeightCache<Hash>>(&self, contract_helper: &C, contract_tree_height: usize) -> anyhow::Result<()> {
        if self.contract_state_tree_updates.len() == 0 {
            anyhow::bail!("contract_state_tree_updates cannot be empty")
        }
        if self.contract_state_tree_updates[0].old_root != self.user_contract_tree_update_proof.old_value && (
            self.user_contract_tree_update_proof.old_value != Hash::get_zero_value() || (self.contract_state_tree_updates[0].old_root != contract_helper.get_contract_zero_hash(self.user_contract_tree_update_proof.index as u32)?)
        ){
            anyhow::bail!("first CST old root does not match UCT old value");
        }
        if self.contract_state_tree_updates.last().as_ref().unwrap().new_root != self.user_contract_tree_update_proof.new_value {

            anyhow::bail!("first CST new root does not match UCT new value");
        }

        if self.user_contract_tree_update_proof.siblings.len() != contract_tree_height {
            anyhow::bail!("invalid tree height in siblings");
        }

        let height = self.contract_state_tree_updates[0].siblings.len();

        for i in 1..self.contract_state_tree_updates.len() {
            if self.contract_state_tree_updates[i].siblings.len() != height {
                anyhow::bail!("invalid tree height in siblings");
            }
            if self.contract_state_tree_updates[i].old_root != self.contract_state_tree_updates[i-1].new_root {
                anyhow::bail!("invalid cst transition proof: current old_root != last new_root, {:?} != {:?}", self.contract_state_tree_updates[i].old_root, self.contract_state_tree_updates[i-1].new_root);
            }
        }


       Ok(())

    }
    pub fn get_double_id_nodes_size_hint(&self) -> usize {
        if self.contract_state_tree_updates.len() == 0 {
            0
        }else{
            self.contract_state_tree_updates.len() * self.contract_state_tree_updates[0].siblings.len() + 2
        }
    }
    /*
    pub fn verify_generate_cst_delta<H: FieldQHasher<F, Hash>>(&self, injestor: &mut CSTUserUpdateStore<Hash>) -> anyhow::Result<()> {


        injestor.verify_injest_uct_delta_merkle_proof::<H>(&self.user_contract_tree_update_proof)?;

        let contract_id = self.user_contract_tree_update_proof.index as u32;


        for p in self.contract_state_tree_updates.iter() {
            injestor.verify_injest_delta_merkle_proof::<H>(contract_id, p)?;
        }

        Ok(())



    }*/
}

#[auto_impl(&, Arc)]
pub trait PSimpleContractHeightCache<Hash> {
    fn add_contract(&self, contract_id: u32, height: u8, zero_hash: Hash);
    fn get_contract_height(&self, contract_id: u32) -> anyhow::Result<u8>;
    fn get_contract_zero_hash(&self, contract_id: u32) -> anyhow::Result<Hash>;
}

#[cfg(feature = "node")]
pub struct DashMapContractHeightCache<Hash> {
    pub mapping: dashmap::DashMap<u32, (u8, Hash)>
}
#[cfg(feature = "node")]
impl<Hash: Copy> DashMapContractHeightCache<Hash> {
    pub fn new() -> Self {
        Self {
            mapping: dashmap::DashMap::new(),
        }
    }
}
#[cfg(feature = "node")]
impl<Hash: Eq + Copy> PSimpleContractHeightCache<Hash> for DashMapContractHeightCache<Hash> {
    fn add_contract(&self, contract_id: u32, height: u8, zero_hash: Hash) {
        self.mapping.insert(contract_id, (height, zero_hash));
    }

    fn get_contract_height(&self, contract_id: u32) -> anyhow::Result<u8> {
        match self.mapping.get(&contract_id) {
            Some(x) => Ok(x.0),
            None => anyhow::bail!("contract {} not loaded",contract_id),
        }
    }

    fn get_contract_zero_hash(&self, contract_id: u32) -> anyhow::Result<Hash> {
        match self.mapping.get(&contract_id) {
            Some(x) => Ok(x.1),
            None => anyhow::bail!("contract {} not loaded",contract_id),
        }
    }
}
