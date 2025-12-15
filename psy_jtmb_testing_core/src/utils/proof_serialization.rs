use parth_core::protocol::core_types::Q256BitHash;
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::proof::PsyTestJTMBProof;

pub fn serialize_jtmb_proof<Hash: Q256BitHash>(
    proof: &PsyTestJTMBProof<Hash>,
) -> anyhow::Result<Vec<u8>> {
    proof.psy_ser_to_bytes_vec()
}

pub fn deserialize_jtmb_proof<Hash: Q256BitHash>(
    data: &[u8],
) -> anyhow::Result<PsyTestJTMBProof<Hash>> {
    
    PsyTestJTMBProof::<Hash>::psy_ser_from_slice(data)
}