use parth_core::{crypto::hash::spiderman::SpidermanUpdateProof, felt::QFelt64, protocol::core_types::Q256BitHash, utils::QPGenRandom};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::{agg::{AggStateTrackableInput, AggStateTransition}, v1::qdata::contract::PQEDContractLeaf};




#[pderive::serialize_clone_f_hash]
#[repr(C)]
pub struct QCBatchDeployContractsCircuitInput<F, Hash> {
    pub deploy_contract_circuit_whitelist: Hash,
    pub spiderman_append_proof: SpidermanUpdateProof<Hash>,
    pub contract_leaves: Vec<PQEDContractLeaf<F, Hash>>,
}

impl<F, Hash: Copy> AggStateTrackableInput<Hash> for QCBatchDeployContractsCircuitInput<F, Hash> {
    fn get_state_transition(&self) -> AggStateTransition<Hash> {
        AggStateTransition {
            state_transition_start: self.spiderman_append_proof.top_line_proof.old_root,
            state_transition_end: self.spiderman_append_proof.top_line_proof.new_root,
        }
    }
}

#[cfg(feature = "rand_gen")]
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for QCBatchDeployContractsCircuitInput<F, Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            deploy_contract_circuit_whitelist: Hash::qp_rand_gen(),
            spiderman_append_proof: SpidermanUpdateProof::qp_rand_gen(),
            contract_leaves: PQEDContractLeaf::qp_rand_gen_vec(rand::random::<u8>() as usize),
        }
    }
}


impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for QCBatchDeployContractsCircuitInput<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}
impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for QCBatchDeployContractsCircuitInput<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
        32 + self.spiderman_append_proof.pio_serialized_size() + 4 + self.contract_leaves.iter().map(|cl| cl.pio_serialized_size()).sum::<usize>()
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.deploy_contract_circuit_whitelist.into_owned_32bytes())?;
        self.spiderman_append_proof.pio_write_to_io(writer)?;
        writer.psy_write_vec_length(self.contract_leaves.len())?;
        for cl in &self.contract_leaves {
            cl.pio_write_to_io(writer)?;
        }
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let whitelist_bytes = reader.psy_read_bytes_fixed::<32>()?;
        let deploy_contract_circuit_whitelist = Hash::from_owned_32bytes(whitelist_bytes);
        let spiderman_append_proof = SpidermanUpdateProof::pio_read_from_io(reader)?;
        let contract_leaves_len = reader.psy_read_vec_length()? as usize;
        let mut contract_leaves = Vec::with_capacity(contract_leaves_len);
        for _ in 0..contract_leaves_len {
            let cl = PQEDContractLeaf::pio_read_from_io(reader)?;
            contract_leaves.push(cl);
        }
        Ok(Self {
            deploy_contract_circuit_whitelist,
            spiderman_append_proof,
            contract_leaves,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    QCBatchDeployContractsCircuitInput,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for QCBatchDeployContractsCircuitInput<F, Hash> {}


pser::impl_psy_ser_basic_tests!(
    QCBatchDeployContractsCircuitInput,
    // Note the use of concrete types here
    {  parth_core::PF, parth_core::PHash },
    qc_batch_deploy_contracts_circuit_input_basic_ser_tests,
);
