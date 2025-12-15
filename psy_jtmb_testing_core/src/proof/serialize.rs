use parth_core::{
    protocol::core_types::Q256BitHash, utils::QPGenRandom,
};
use psy_core::job::job_id::ProvingJobCircuitType;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
use crate::proof::PsyTestJTMBProofVerifierData;
use crate::proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierDataWithFingerprint};

impl<Hash: QPGenRandom> QPGenRandom for PsyTestJTMBProof<Hash>
{
    fn qp_rand_gen() -> Self {
        Self {
            public_inputs_hash: Hash::qp_rand_gen(),
            signature: QPGenRandom::qp_rand_gen(),
        }
    }
}

impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PsyTestJTMBProof<Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 96;
}
impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for PsyTestJTMBProof<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
       Self::FIXED_SIZE
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_bytes_fixed(&self.public_inputs_hash.into_owned_32bytes())?;
        writer.psy_write_bytes_fixed(&self.signature)?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let public_inputs_hash_bytes = reader.psy_read_bytes_fixed::<32>()?;
        let public_inputs_hash = Hash::from_owned_32bytes(public_inputs_hash_bytes);
        let signature = reader.psy_read_bytes_fixed::<64>()?;
        Ok(Self {
            public_inputs_hash,
            signature,
        })
    }

}

#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PsyTestJTMBProof,
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for PsyTestJTMBProof<Hash> {}

pser::impl_psy_ser_basic_tests!(
    PsyTestJTMBProof,
    // Note the use of concrete types here
    {  parth_core::PHash },
    psy_test_jtmb_proof_basic_ser_tests
);



impl QPGenRandom for PsyTestJTMBProofVerifierData {
    fn qp_rand_gen() -> Self {
        Self {
            circuit_type: ProvingJobCircuitType::qp_rand_gen().to_u8() as u32,
            circuit_config_fingerprint: QPGenRandom::qp_rand_gen(),
            signer_public_key_sign: (rand::random::<u8>() & 0x03) as u32,
            signer_public_key_x: QPGenRandom::qp_rand_gen(),
        }
    }
}

impl PsyCanonicalSerializeMetadata for PsyTestJTMBProofVerifierData {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 72;
}
impl FallbackPsySerializeCanonical for PsyTestJTMBProofVerifierData {
    fn fallback_pio_serialized_size(&self) -> usize {
       Self::FIXED_SIZE
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_u32(self.circuit_type)?;
        writer.psy_write_u32(self.signer_public_key_sign)?;
        writer.psy_write_bytes_fixed(&self.signer_public_key_x)?;
        writer.psy_write_bytes_fixed(&self.circuit_config_fingerprint)?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let circuit_type = reader.psy_read_u32()?;
        let signer_public_key_sign = reader.psy_read_u32()?;
        if (signer_public_key_sign & 0xFF) != signer_public_key_sign {
            anyhow::bail!("Invalid signer public key sign byte");
        }
        let signer_public_key_x = reader.psy_read_bytes_fixed::<32>()?;
        let circuit_config_fingerprint = reader.psy_read_bytes_fixed::<32>()?;
        Ok(Self {
            circuit_type,
            signer_public_key_sign,
            signer_public_key_x,
            circuit_config_fingerprint,
        })
    }

}
#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(PsyTestJTMBProofVerifierData);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl psy_serialize::AutoImplementFallbackPsySerializeCanonical for PsyTestJTMBProofVerifierData {}


pser::impl_psy_ser_basic_tests!(
    PsyTestJTMBProofVerifierData,
    // Note the use of concrete types here
    {  },
    psy_test_jtmb_proof_verifier_data_basic_ser_tests
);

impl <Hash: QPGenRandom> QPGenRandom for PsyTestJTMBProofVerifierDataWithFingerprint<Hash>
{
    fn qp_rand_gen() -> Self {
        Self {
            verifier_data: PsyTestJTMBProofVerifierData::qp_rand_gen(),
            fingerprint: Hash::qp_rand_gen(),
        }
    }
}
impl<Hash: Q256BitHash> PsyCanonicalSerializeMetadata for PsyTestJTMBProofVerifierDataWithFingerprint<Hash> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 72 + 32;
}
impl<Hash: Q256BitHash> FallbackPsySerializeCanonical for PsyTestJTMBProofVerifierDataWithFingerprint<Hash> {
    fn fallback_pio_serialized_size(&self) -> usize {
       Self::FIXED_SIZE
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        self.verifier_data.pio_write_to_io(writer)?;
        writer.psy_write_bytes_fixed(&self.fingerprint.into_owned_32bytes())?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let verifier_data = PsyTestJTMBProofVerifierData::fallback_pio_read_from_io(reader)?;
        let fingerprint = Hash::from_owned_32bytes(reader.psy_read_bytes_fixed::<32>()?);
        Ok(Self {
            verifier_data,
            fingerprint,
        })
    }
}
#[cfg(all(feature = "serialize_speedy", target_endian = "little"))]
psy_serialize::impl_psy_canonical_serialize_for_speedy!(
    PsyTestJTMBProofVerifierDataWithFingerprint, 
    { Hash: Q256BitHash } => { Hash }
);
#[cfg(not(all(feature = "serialize_speedy", target_endian = "little")))]
impl<Hash: Q256BitHash> psy_serialize::AutoImplementFallbackPsySerializeCanonical for PsyTestJTMBProofVerifierDataWithFingerprint<Hash> {}

pser::impl_psy_ser_basic_tests!(
    PsyTestJTMBProofVerifierDataWithFingerprint,
    // Note the use of concrete types here
    {  parth_core::PHash },
    psy_test_jtmb_proof_verifier_data_with_fingerprint_basic_ser_tests
);