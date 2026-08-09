use std::marker::PhantomData;

use plonky2::{
    gates::gate::GateRef,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::{data::qhashout::QHashOut, utils::debug_timer::DebugTimer};
use psy_crypto::signature::secp256k1::core::{PsyCompressedSecp256K1Signature, PsyPreparedSecp256K1Signature};

use super::traits::qstandard::QStandardCircuit;
use crate::{
    crypto::secp256k1::gadget::{Secp256K1Gadget, DOGE_PSY_PREFIX, EIP191_PREFIX_32},
    proof_minifier::pm_chain::PsyProofMinifierChain,
    u32::gates::comparison::ComparisonGate,
};

/// Identifies which message-prefix flavor a secp256k1 signature circuit is built
/// with. The prefix is the ONLY difference between flavors — the gadget wiring,
/// minifier chain and `prove` are fully shared via [`Secp256K1SignatureCircuitBase`].
pub trait Secp256K1SignatureFlavor: Send + Sync + 'static {
    const PREFIX: &'static [u8];
}

/// Classic Doge/Psy flavor: the ECDSA message is the raw sighash (no prefix).
#[derive(Debug, Clone, Copy)]
pub struct DogePsySignatureFlavor;
impl Secp256K1SignatureFlavor for DogePsySignatureFlavor {
    const PREFIX: &'static [u8] = DOGE_PSY_PREFIX;
}

/// EIP-191 `personal_sign` flavor: the ECDSA message is
/// `keccak256("\x19Ethereum Signed Message:\n32" || sighash)`, while the raw
/// sighash is still bound into `combined_hash`.
#[derive(Debug, Clone, Copy)]
pub struct EthPersonalSignSignatureFlavor;
impl Secp256K1SignatureFlavor for EthPersonalSignSignatureFlavor {
    const PREFIX: &'static [u8] = EIP191_PREFIX_32;
}

#[derive(Debug)]
pub struct Secp256K1SignatureCircuitBase<M: Secp256K1SignatureFlavor, C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub signature_gadget: Secp256K1Gadget,
    pub base_circuit_data: CircuitData<C::F, C, D>,
    pub minifier_chain: PsyProofMinifierChain<D, C::F, C>,
    _flavor: PhantomData<M>,
}

/// Classic Doge/Psy secp256k1 signature circuit (raw sighash, no prefix).
pub type Secp256K1SignatureCircuit<C, const D: usize> = Secp256K1SignatureCircuitBase<DogePsySignatureFlavor, C, D>;
/// EIP-191 `personal_sign` secp256k1 signature circuit (keccak-prefixed).
pub type EthPersonalSignSecp256K1SignatureCircuit<C, const D: usize> = Secp256K1SignatureCircuitBase<EthPersonalSignSignatureFlavor, C, D>;

impl<M: Secp256K1SignatureFlavor, C: GenericConfig<D>, const D: usize> Clone for Secp256K1SignatureCircuitBase<M, C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<M: Secp256K1SignatureFlavor, C: GenericConfig<D>, const D: usize> Secp256K1SignatureCircuitBase<M, C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let signature_gadget = Secp256K1Gadget::add_virtual_to::<C::Hasher, C::F, D>(&mut builder, M::PREFIX);

        builder.register_public_inputs(&signature_gadget.combined_hash.elements);
        let circuit_data = builder.build::<C>();

        let added_gates_for_minifier = [GateRef::new(ComparisonGate::new(32, 16))];

        let minifier_chain =
            PsyProofMinifierChain::<D, C::F, C>::new_add_gates(&circuit_data.verifier_only, &circuit_data.common, 2, Some(&added_gates_for_minifier));

        Self {
            base_circuit_data: circuit_data,
            signature_gadget,
            minifier_chain,
            _flavor: PhantomData,
        }
    }
    pub fn prove(&self, compressed_signature: &PsyCompressedSecp256K1Signature) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let prepared_signature: PsyPreparedSecp256K1Signature<C::F> = compressed_signature.try_into()?;

        let mut timer = DebugTimer::new("Secp256K1SignatureCircuit::Prove");
        tracing::info!("start prove base secp256k1 signature");
        timer.lap("start prove base");
        let mut pw = PartialWitness::new();
        self.signature_gadget.set_witness_public_keys_update(
            &mut pw,
            &prepared_signature.public_key,
            &prepared_signature.signature,
            prepared_signature.message,
        )?;
        let base_proof = self.base_circuit_data.prove(pw)?;
        timer.lap("end prove base");
        tracing::info!("end prove base secp256k1 signature");
        timer.lap("start minifier");
        let minified_proof = self.minifier_chain.prove(&base_proof)?;
        timer.lap("end minifier");
        Ok(minified_proof)
    }
}

impl<M: Secp256K1SignatureFlavor, C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for Secp256K1SignatureCircuitBase<M, C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        QHashOut(self.minifier_chain.get_fingerprint())
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        self.minifier_chain.get_verifier_data()
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        self.minifier_chain.get_common_data()
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        plonk::config::{Hasher, PoseidonGoldilocksConfig},
    };
    use psy_client_common::data::{qhashout::QHashOut, secp256k1::CompressedPublicKey};
    use psy_crypto::signature::secp256k1::wallet::{ethereum_address_for_verifying_key, hash_no_pad_compressed_public_key, recover_eth_personal_signature};

    use super::EthPersonalSignSecp256K1SignatureCircuit;

    #[test]
    fn eth_personal_host_signature_proves_and_binds_raw_message() {
        type C = PoseidonGoldilocksConfig;
        const D: usize = 2;

        let circuit = EthPersonalSignSecp256K1SignatureCircuit::<C, D>::new();
        let signing_key = k256::ecdsa::SigningKey::from_slice(&[13u8; 32]).unwrap();
        let message = psy_client_common::data::base_types::hash256::Hash256([0x51; 32]);
        let digest = psy_crypto::signature::secp256k1::wallet::eth_personal_sign_digest(&message.0);
        let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&digest).unwrap();
        let address_digest = ethereum_address_for_verifying_key(signing_key.verifying_key());
        let mut signature_bytes = [0u8; 65];
        signature_bytes[..64].copy_from_slice(&signature.to_bytes());
        signature_bytes[64] = recovery_id.to_byte();
        let recovered = recover_eth_personal_signature(address_digest, message, signature_bytes).unwrap();

        let proof = circuit.prove(&recovered).unwrap();
        circuit.minifier_chain.verify(proof.clone()).unwrap();

        let public_key_hash = hash_no_pad_compressed_public_key::<GoldilocksField, plonky2::hash::poseidon::PoseidonPermutation<GoldilocksField>>(
            CompressedPublicKey(recovered.public_key),
        );
        let message_hash = QHashOut::<GoldilocksField>::from(recovered.message);
        let expected = plonky2::hash::poseidon::PoseidonHash::two_to_one(message_hash.0, public_key_hash.0);
        assert_eq!(proof.public_inputs, expected.elements);
    }
}
