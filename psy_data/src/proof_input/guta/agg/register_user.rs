

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
            stats: GUTAStats::<F>::get_zero_value(),
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
         GlobalUserTreeAggregatorHeader::<F, Hash>::FIXED_SIZE + 4 + 32*self.top_line_siblings.len() + 4 + self.guta_register_user_inputs.iter().map(|x| x.pio_serialized_size()).sum::<usize>()
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

#[cfg(test)]
mod behavior_tests {
    use super::*;
    use parth_core::{crypto::hash::traits::{FromU64x4, ZeroableHash}, pgoldilocks::PoseidonHasher, PF, PHash};
    use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

    #[test]
    fn dummy_registration_input_has_requested_heights_and_values() {
        let leaf = PHash::from_u64x4([7, 0, 0, 0]);
        let public_key = PHash::from_u64x4([8, 0, 0, 0]);
        let input = GUTARegisterUserFullInput::new_dummy(3, 2, leaf, public_key);

        assert_eq!(input.user_registration_tree_merkle_proof.siblings.len(), 3);
        assert_eq!(input.user_registration_tree_merkle_proof.value, public_key);
        assert_eq!(input.global_user_tree_update_proof.siblings.len(), 2);
        assert_eq!(input.global_user_tree_update_proof.new_value, leaf);
        assert_eq!(input.global_user_tree_update_proof.old_root, PHash::get_zero_value());
    }

    #[test]
    fn no_change_public_input_hash_commits_to_root_and_whitelist() {
        let input = GUTANoChangeFullInput {
            checkpoint_tree_proof: MerkleProofCore {
                siblings: vec![],
                root: PHash::from_u64x4([1, 0, 0, 0]),
                value: PHash::get_zero_value(),
                index: 0,
            },
            checkpoint_leaf: PQEDCheckpointLeafCompactWithStateRoots::qp_rand_gen(),
        };
        let whitelist = PHash::from_u64x4([2, 0, 0, 0]);
        let hash = input.get_public_inputs_hash_no_rewards_tag::<PF, PoseidonHasher>(whitelist);
        assert_ne!(hash, PHash::get_zero_value());
        assert_ne!(hash, input.get_public_inputs_hash_no_rewards_tag::<PF, PoseidonHasher>(PHash::from_u64x4([3, 0, 0, 0])));
    }

    // The fallback writer must emit exactly the canonical (speedy) encoding, and
    // that payload must round-trip through the canonical reader. The fallback
    // reader itself cannot be exercised here: chained nested speedy stream reads
    // desynchronize the shared cursor (reported production bug).
    #[test]
    fn no_change_full_input_fallback_write_matches_canonical_encoding() {
        let input = GUTANoChangeFullInput::<PHash>::qp_rand_gen();
        let bytes = input.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(bytes.len(), input.fallback_pio_serialized_size());
        assert_eq!(bytes, input.psy_ser_to_bytes_vec().unwrap());
        assert_eq!(GUTANoChangeFullInput::<PHash>::psy_ser_from_slice(&bytes).unwrap(), input);
    }

    #[test]
    fn register_user_full_input_fallback_write_matches_canonical_encoding() {
        let input = GUTARegisterUserFullInput::<PHash>::qp_rand_gen();
        let bytes = input.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(bytes.len(), input.fallback_pio_serialized_size());
        assert_eq!(bytes, input.psy_ser_to_bytes_vec().unwrap());
        assert_eq!(GUTARegisterUserFullInput::<PHash>::psy_ser_from_slice(&bytes).unwrap(), input);
    }

    #[test]
    fn verify_register_users_circuit_input_fallback_write_with_and_without_members() {
        let mut input = VerifyGUTARegisterUsersCircuitInputSimple::<PF, PHash>::qp_rand_gen();
        assert!(!input.top_line_siblings.is_empty());
        assert!(!input.guta_register_user_inputs.is_empty());

        let bytes = input.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(bytes, input.psy_ser_to_bytes_vec().unwrap());
        assert_eq!(VerifyGUTARegisterUsersCircuitInputSimple::<PF, PHash>::psy_ser_from_slice(&bytes).unwrap(), input);

        // Empty siblings and inputs exercise the zero-length vector paths.
        input.top_line_siblings.clear();
        input.guta_register_user_inputs.clear();
        let bytes = input.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(
            bytes.len(),
            GlobalUserTreeAggregatorHeader::<PF, PHash>::FIXED_SIZE + 4 + 4
        );
        assert_eq!(bytes, input.psy_ser_to_bytes_vec().unwrap());
        assert_eq!(VerifyGUTARegisterUsersCircuitInputSimple::<PF, PHash>::psy_ser_from_slice(&bytes).unwrap(), input);
    }

    #[test]
    fn only_register_users_input_fallback_write_empty_and_non_empty() {
        let mut input = GUTAOnlyRegisterUsersInput::<PHash>::qp_rand_gen();
        let bytes = input.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(bytes.len(), input.fallback_pio_serialized_size());
        assert_eq!(bytes, input.psy_ser_to_bytes_vec().unwrap());
        assert_eq!(GUTAOnlyRegisterUsersInput::<PHash>::psy_ser_from_slice(&bytes).unwrap(), input);

        input.guta_register_user_inputs.clear();
        let bytes = input.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(bytes.len(), 32 + 4);
        assert_eq!(bytes, input.psy_ser_to_bytes_vec().unwrap());
        assert_eq!(GUTAOnlyRegisterUsersInput::<PHash>::psy_ser_from_slice(&bytes).unwrap(), input);
    }
}
