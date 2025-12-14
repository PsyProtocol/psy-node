use parth_common::secp256k1::{MemorySecp256K1SinglePrivateKeyWallet, Secp256K1VerifierHelper};
use parth_core::{
    crypto::{
        hash::traits::FieldQHasher,
        secp256k1::{CompressedPublicKey, QEDCompressedSecp256K1Signature, Secp256K1Verifier, Secp256K1WalletProvider},
    },
    data::hash::hash256::Hash256,
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use crate::utils::serde_array::serde_arrays;

fn compute_message_hash_jtmb_proof<F: QFelt64, Hash: Q256BitHash + QFHashBase<F>, Hasher: FieldQHasher<F, Hash>>(
    public_inputs_hash: Hash,
    circuit_config_fingerprint: [u8; 32],
    circuit_type: u32,
) -> [u8; 32] {
    let circuit_type_as_felt = F::from_u32_value(circuit_type);
    let public_inputs_hash_felts = public_inputs_hash.to_4_felts();
    let circuit_config_fingerprint_hash_felts = Hash::from_owned_32bytes(circuit_config_fingerprint).to_4_felts();
    Hasher::q_hash_many(&[
        circuit_type_as_felt,
        public_inputs_hash_felts[0],
        public_inputs_hash_felts[1],
        public_inputs_hash_felts[2],
        public_inputs_hash_felts[3],
        circuit_config_fingerprint_hash_felts[0],
        circuit_config_fingerprint_hash_felts[1],
        circuit_config_fingerprint_hash_felts[2],
        circuit_config_fingerprint_hash_felts[3],
    ])
    .into_owned_32bytes()
}

#[pderive::serialize_copy]
#[repr(C)]
pub struct PsyTestJTMBProof<Hash> {
    pub public_inputs_hash: Hash,

    #[serde(with = "serde_arrays")]
    pub signature: [u8; 64],
}

#[pderive::serialize_copy]
#[repr(C)]
pub struct PsyTestJTMBProofVerifierData {
    pub circuit_type: u32,
    pub signer_public_key_sign: u32,
    pub signer_public_key_x: [u8; 32],
    pub circuit_config_fingerprint: [u8; 32],
}

impl PsyTestJTMBProofVerifierData {
    pub fn new_from_compressed_public_key(
        circuit_type: u32,
        circuit_config_fingerprint: [u8; 32],
        compressed_public_key: &CompressedPublicKey,
    ) -> Self {
        let mut signer_public_key_x = [0u8; 32];
        signer_public_key_x.copy_from_slice(&compressed_public_key.0[1..33]);
        Self {
            circuit_type,
            circuit_config_fingerprint,
            signer_public_key_sign: compressed_public_key.0[0] as u32,
            signer_public_key_x,
        }
    }
    pub fn get_signer_public_key(&self) -> CompressedPublicKey {
        let mut compressed = [0u8; 33];
        compressed[0] = (self.signer_public_key_sign & 0xFF) as u8;
        compressed[1..33].copy_from_slice(&self.signer_public_key_x);
        CompressedPublicKey(compressed)
    }
    pub fn get_fingerprint<Hash: QFHashBase<F> + Q256BitHash, Hasher: FieldQHasher<F, Hash>, F: QFelt64>(&self) -> Hash {
        let circuit_type_as_felt = F::from_u32_value(self.circuit_type);
        let top_public_key_byte_as_felt = F::from_u8_value((self.signer_public_key_sign & 0xFF) as u8);
        let public_key_x_felts = Hash::from_owned_32bytes(self.signer_public_key_x).to_4_felts();
        let circuit_config_fingerprint_hash_felts = Hash::from_owned_32bytes(self.circuit_config_fingerprint).to_4_felts();
        Hasher::q_hash_many(&[
            circuit_type_as_felt,
            top_public_key_byte_as_felt,
            public_key_x_felts[0],
            public_key_x_felts[1],
            public_key_x_felts[2],
            public_key_x_felts[3],
            circuit_config_fingerprint_hash_felts[0],
            circuit_config_fingerprint_hash_felts[1],
            circuit_config_fingerprint_hash_felts[2],
            circuit_config_fingerprint_hash_felts[3],
        ])
    }
    pub fn get_message_hash_for_public_inputs<F: QFelt64, Hash: QFHashBase<F> + Q256BitHash, Hasher: FieldQHasher<F, Hash>>(
        &self,
        public_inputs_hash: Hash,
    ) -> [u8; 32] {
        compute_message_hash_jtmb_proof::<F, Hash, Hasher>(public_inputs_hash, self.circuit_config_fingerprint, self.circuit_type)
    }
    pub fn verify_proof<Hasher: FieldQHasher<F, Hash>, Hash: QFHashBase<F> + Q256BitHash, F: QFelt64>(
        &self,
        proof: &PsyTestJTMBProof<Hash>,
    ) -> anyhow::Result<()> {
        if (self.signer_public_key_sign & 0xFF) != self.signer_public_key_sign {
            anyhow::bail!("Invalid signer public key sign byte");
        }

        let message_hash = self.get_message_hash_for_public_inputs::<F, Hash, Hasher>(proof.public_inputs_hash);
        let signature = QEDCompressedSecp256K1Signature {
            public_key: self.get_signer_public_key().0,
            signature: proof.signature,
            message: Hash256(message_hash),
        };
        Secp256K1VerifierHelper::secp256k1_verify(&signature)
    }

    pub fn to_record_with_fingerprint<Hash: QFHashBase<F> + Q256BitHash, Hasher: FieldQHasher<F, Hash>, F: QFelt64>(
        &self,
    ) -> PsyTestJTMBProofVerifierDataWithFingerprint<Hash> {
        let fingerprint = self.get_fingerprint::<Hash, Hasher, F>();
        PsyTestJTMBProofVerifierDataWithFingerprint {
            verifier_data: self.clone(),
            fingerprint,
        }
    }
    pub fn generate_proof_with_signer<Hasher: FieldQHasher<F, Hash>, Hash: QFHashBase<F> + Q256BitHash, F: QFelt64, Signer: Secp256K1WalletProvider>(
        &self,
        public_inputs_hash: Hash,
        signing_key: &Signer,
    ) -> anyhow::Result<PsyTestJTMBProof<Hash>> {
        let message_hash = self.get_message_hash_for_public_inputs::<F, Hash, Hasher>(public_inputs_hash);
        let signer_public_key = self.get_signer_public_key();
        let signature = signing_key.sign(&signer_public_key, Hash256(message_hash))?;

        Ok(PsyTestJTMBProof {
            public_inputs_hash,
            signature: signature.signature,
        })
    }
    pub fn generate_proof_with_private_key<Hasher: FieldQHasher<F, Hash>, Hash: QFHashBase<F> + Q256BitHash, F: QFelt64>(
        &self,
        public_inputs_hash: Hash,
        private_key: [u8; 32],
    ) -> anyhow::Result<PsyTestJTMBProof<Hash>> {
        let wallet = MemorySecp256K1SinglePrivateKeyWallet::new_from_private_key_bytes(&private_key)?;
        self.generate_proof_with_signer::<Hasher, Hash, F, _>(
            public_inputs_hash,
            &wallet,
        )
    }
}


#[pderive::serialize_copy]
#[repr(C)]
pub struct PsyTestJTMBProofVerifierDataWithFingerprint<Hash> {
    pub verifier_data: PsyTestJTMBProofVerifierData,
    pub fingerprint: Hash,
}