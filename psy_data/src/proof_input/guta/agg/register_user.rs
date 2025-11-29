

use std::hash::Hash;

use parth_core::{crypto::hash::{merkle_proof::{DeltaMerkleProofCore, MerkleProofCore}, traits::{FieldQHasher, QFieldHashable, ZeroableHash}}, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase}, utils::QPGenRandom};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::{guta::{header::GlobalUserTreeAggregatorHeader, stats::GUTAStats, sub_tree_transition::SubTreeNodeStateTransition}, v1::qdata::checkpoint::PQEDCheckpointLeafCompactWithStateRoots};
use psy_serialize::FallbackPsySerializeCanonical;



#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash))]
pub struct GUTANoChangeFullInput<Hash> {
    pub checkpoint_tree_proof: MerkleProofCore<Hash>,
    pub checkpoint_leaf: PQEDCheckpointLeafCompactWithStateRoots<Hash>,
}


impl<Hash> GUTANoChangeFullInput<Hash> {
    pub fn get_public_inputs_hash_no_rewards_tag<F: QFelt64, Hasher: FieldQHasher<F, Hash>>(&self, guta_circuit_whitelist: Hash) -> Hash where Hash: QFHashBase<F>{
        let state_transition = SubTreeNodeStateTransition::<F, Hash> {
                old_node_value: self.checkpoint_leaf.global_state_roots.user_tree_root,
                new_node_value: self.checkpoint_leaf.global_state_roots.user_tree_root,
                node_index: F::ZERO_VALUE,
                node_level: F::ZERO_VALUE,
        };
        let guta_header = GlobalUserTreeAggregatorHeader::<F, Hash> {
            guta_circuit_whitelist,
            checkpoint_tree_root: self.checkpoint_tree_proof.root,
            state_transition,
            stats: GUTAStats {
                fees_collected: F::ZERO_VALUE,
                user_ops_processed: F::ZERO_VALUE,
                total_transactions: F::ZERO_VALUE,
                slots_modified: F::ZERO_VALUE,
            },
            total_aggregation_proofs_generated: F::from_u8_value(1),
        };
        let guta_header_hash = guta_header.qfhash::<Hasher>();
        guta_header_hash
    }
}
impl<Hash: QPGenRandom> QPGenRandom for GUTANoChangeFullInput<Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            checkpoint_tree_proof: MerkleProofCore::<Hash>::qp_rand_gen(),
            checkpoint_leaf: PQEDCheckpointLeafCompactWithStateRoots::<Hash>::qp_rand_gen(),
        }
    }
}

impl< Hash: Q256BitHash> PsyCanonicalSerializeMetadata for GUTANoChangeFullInput<Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}
impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for GUTANoChangeFullInput<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {

         self.checkpoint_tree_proof.pio_serialized_size() +
         self.checkpoint_leaf.pio_serialized_size() 
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.checkpoint_tree_proof.pio_write_to_io(writer)?;
        self.checkpoint_leaf.pio_write_to_io(writer)?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let checkpoint_tree_proof = MerkleProofCore::pio_read_from_io(reader)?;
        let checkpoint_leaf = PQEDCheckpointLeafCompactWithStateRoots::pio_read_from_io(reader)?;
        Ok(Self {
            checkpoint_tree_proof,                                                            
            checkpoint_leaf,
        })
    }
}
#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    GUTANoChangeFullInput,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for GUTANoChangeFullInput<Hash> {}


pser::impl_psy_ser_basic_tests_fallback!(
    GUTANoChangeFullInput,
    { parth_core::PHash },
    guta_no_change_full_input_tests
);



#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash))]
pub struct GUTARegisterUserFullInput<Hash> {
    pub user_registration_tree_merkle_proof: MerkleProofCore<Hash>,
    pub global_user_tree_update_proof: DeltaMerkleProofCore<Hash>,
}

impl<Hash: QPGenRandom> QPGenRandom for GUTARegisterUserFullInput<Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            user_registration_tree_merkle_proof: MerkleProofCore::<Hash>::qp_rand_gen(),
            global_user_tree_update_proof: DeltaMerkleProofCore::<Hash>::qp_rand_gen(),
        }
    }
}


impl<Hash: Copy + ZeroableHash> GUTARegisterUserFullInput<Hash> {


    pub fn new_dummy(global_user_tree_height: usize, height: usize, dummy_user_leaf_hash: Hash, fake_public_key: Hash) -> Self {

        let siblings = (0..global_user_tree_height).map(|_| Hash::get_zero_value()).collect::<Vec<_>>();
        let user_registration_tree_merkle_proof = MerkleProofCore {
            siblings,
            root: Hash::get_zero_value(),
            value : fake_public_key,
            index: 0,
        };

        let dmp_siblings = (0..height).map(|_| Hash::get_zero_value()).collect();
        let global_user_tree_update_proof = DeltaMerkleProofCore{
            siblings: dmp_siblings,
            old_root: Hash::get_zero_value(),
            old_value: Hash::get_zero_value(),
            new_root: Hash::get_zero_value(),
            new_value: dummy_user_leaf_hash,
            index: 0,
        };

        Self {
            user_registration_tree_merkle_proof,
            global_user_tree_update_proof,
        }

    }
}

impl< Hash: Q256BitHash> PsyCanonicalSerializeMetadata for GUTARegisterUserFullInput<Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}
impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for GUTARegisterUserFullInput<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {

         self.user_registration_tree_merkle_proof.pio_serialized_size() +
         self.global_user_tree_update_proof.pio_serialized_size() 
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.user_registration_tree_merkle_proof.pio_write_to_io(writer)?;
        self.global_user_tree_update_proof.pio_write_to_io(writer)?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let user_registration_tree_merkle_proof = MerkleProofCore::pio_read_from_io(reader)?;
        let global_user_tree_update_proof = DeltaMerkleProofCore::pio_read_from_io(reader)?;
        Ok(Self {
            user_registration_tree_merkle_proof,                                                            
            global_user_tree_update_proof,
        })
    }
}
#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    GUTARegisterUserFullInput,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for GUTARegisterUserFullInput<Hash> {}


pser::impl_psy_ser_basic_tests_fallback!(
    GUTARegisterUserFullInput,
    { parth_core::PHash },
    guta_register_user_full_input_tests
);



#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyGUTARegisterUsersCircuitInputSimple<F, Hash> {
    pub guta_proof_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub top_line_siblings: Vec<Hash>,
    pub guta_register_user_inputs: Vec<GUTARegisterUserFullInput<Hash>>
}
impl<F: QPGenRandom, Hash: QPGenRandom> QPGenRandom for VerifyGUTARegisterUsersCircuitInputSimple<F, Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            guta_proof_header: GlobalUserTreeAggregatorHeader::<F, Hash>::qp_rand_gen(),
            top_line_siblings: QPGenRandom::qp_rand_gen_vec(5),
            guta_register_user_inputs: QPGenRandom::qp_rand_gen_vec(3),
        }
    }
}


impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for VerifyGUTARegisterUsersCircuitInputSimple<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}
impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical for VerifyGUTARegisterUsersCircuitInputSimple<F, Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
         GlobalUserTreeAggregatorHeader::<F, Hash>::FIXED_SIZE + 4 * 32*self.top_line_siblings.len() + 4 + self.guta_register_user_inputs.iter().map(|x| x.pio_serialized_size()).sum::<usize>()
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.guta_proof_header.pio_write_to_io(writer)?;
        writer.psy_write_vec_length(self.top_line_siblings.len())?;
        for sibling in self.top_line_siblings.iter() {
            writer.psy_write_bytes_fixed(&sibling.into_owned_32bytes())?;
        }
        writer.psy_write_vec_length(self.guta_register_user_inputs.len())?;
        for input in self.guta_register_user_inputs.iter() {
            input.pio_write_to_io(writer)?;
        }
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let guta_proof_header = GlobalUserTreeAggregatorHeader::<F, Hash>::pio_read_from_io(reader)?;
        let top_line_siblings_len = reader.psy_read_vec_length()?;
        let mut top_line_siblings = Vec::with_capacity(top_line_siblings_len);
        for _ in 0..top_line_siblings_len {
            let sibling = Hash::from_owned_32bytes( reader.psy_read_bytes_32()?);
            top_line_siblings.push(sibling);
        }
        let guta_register_user_inputs_len = reader.psy_read_vec_length()?;
        let mut guta_register_user_inputs = Vec::with_capacity(guta_register_user_inputs_len);
        for _ in 0..guta_register_user_inputs_len {
            let input = GUTARegisterUserFullInput::<Hash>::pio_read_from_io(reader)?;
            guta_register_user_inputs.push(input);
        }
        Ok(Self {
            guta_proof_header,
            top_line_siblings,
            guta_register_user_inputs,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    VerifyGUTARegisterUsersCircuitInputSimple,
    { F: QFelt64, Hash: Q256BitHash } => { F, Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<F: QFelt64, Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for VerifyGUTARegisterUsersCircuitInputSimple<F, Hash> {}


pser::impl_psy_ser_basic_tests_fallback!(
    VerifyGUTARegisterUsersCircuitInputSimple,
    { parth_core::PF, parth_core::PHash },
    verify_guta_register_users_circuit_input_simple_tests
);






#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash))]
pub struct GUTAOnlyRegisterUsersInput<Hash> {
    pub checkpoint_tree_root: Hash,
    pub guta_register_user_inputs: Vec<GUTARegisterUserFullInput<Hash>>,
}
impl<Hash: QPGenRandom> QPGenRandom for GUTAOnlyRegisterUsersInput<Hash> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self {
            checkpoint_tree_root: Hash::qp_rand_gen(),
            guta_register_user_inputs: QPGenRandom::qp_rand_gen_vec(3),
        }
    }
}



impl< Hash: Q256BitHash> PsyCanonicalSerializeMetadata for GUTAOnlyRegisterUsersInput<Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}
impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for GUTAOnlyRegisterUsersInput<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {

            32 + 4 + self.guta_register_user_inputs.iter().map(|x| x.pio_serialized_size()).sum::<usize>()
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.checkpoint_tree_root.into_owned_32bytes())?;
        writer.psy_write_vec_length(self.guta_register_user_inputs.len())?;
        for input in self.guta_register_user_inputs.iter() {
            input.pio_write_to_io(writer)?;
        }
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let checkpoint_tree_root = Hash::from_owned_32bytes( reader.psy_read_bytes_32()?);
        let guta_register_user_inputs_len = reader.psy_read_vec_length()?;
        let mut guta_register_user_inputs = Vec::with_capacity(guta_register_user_inputs_len);
        for _ in 0..guta_register_user_inputs_len {
            let input = GUTARegisterUserFullInput::<Hash>::pio_read_from_io(reader)?;
            guta_register_user_inputs.push(input);
        }
        Ok(Self {
            checkpoint_tree_root,
            guta_register_user_inputs,
        })
    }
}
#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    GUTAOnlyRegisterUsersInput,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for GUTAOnlyRegisterUsersInput<Hash> {}


pser::impl_psy_ser_basic_tests_fallback!(
    GUTAOnlyRegisterUsersInput,
    { parth_core::PHash },
    guta_only_register_users_input_tests
);

