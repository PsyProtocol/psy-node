use plonky2::{
    hash::hash_types::HashOut,
    plonk::{
        config::{AlgebraicHasher, GenericConfig, Hasher},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::signature::zk::{data::ZKPublicKeyInfo, wallet::SimplePsyPrivateKey};

use super::core::PsyBasicZKSignatureCircuit;
use crate::circuits::traits::qstandard::QStandardCircuit;

#[derive(Debug, Clone)]
pub struct SimplePsyZKSignatureManager<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub circuit: PsyBasicZKSignatureCircuit<C, D>,
    public_key_to_private_key_store: hashbrown::HashMap<QHashOut<C::F>, SimplePsyPrivateKey<C::F>>,
}

impl<C: GenericConfig<D> + 'static, const D: usize> SimplePsyZKSignatureManager<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new() -> Self {
        Self {
            circuit: PsyBasicZKSignatureCircuit::new(),
            public_key_to_private_key_store: hashbrown::HashMap::new(),
        }
    }

    pub fn verify_simple_zk_signature(
        &self,
        public_key: QHashOut<C::F>,
        public_key_param: QHashOut<C::F>,
        sig_hash: QHashOut<C::F>,
        proof: ProofWithPublicInputs<C::F, C, D>,
    ) -> bool {
        if proof.public_inputs.len() != 4 {
            return false;
        }
        let expected_public_key = QHashOut(C::Hasher::two_to_one(self.circuit.get_fingerprint().0, public_key_param.0));
        let expected_public_inputs = C::Hasher::two_to_one(sig_hash.0, public_key_param.0);
        let proof_public_inputs_hash = HashOut {
            elements: [
                proof.public_inputs[0],
                proof.public_inputs[1],
                proof.public_inputs[2],
                proof.public_inputs[3],
            ],
        };

        if expected_public_key.eq(&public_key) && expected_public_inputs.eq(&proof_public_inputs_hash) {
            self.circuit.minifier_chain.verify(proof).is_ok()
        } else {
            false
        }
    }
    pub fn get_zksig_circuit_fingerprint(&self) -> QHashOut<C::F> {
        self.circuit.get_fingerprint()
    }
    pub fn add_private_key_get_info(&mut self, private_key: SimplePsyPrivateKey<C::F>) -> ZKPublicKeyInfo<C::F> {
        let public_key_param = private_key.get_public_key_param::<C::Hasher>();

        let fingerprint = self.get_zksig_circuit_fingerprint();
        self.add_private_key(private_key);

        ZKPublicKeyInfo {
            fingerprint,
            public_key_param,
        }
    }

    pub fn get_public_key_info(&self, private_key: SimplePsyPrivateKey<C::F>) -> ZKPublicKeyInfo<C::F> {
        let public_key_param = private_key.get_public_key_param::<C::Hasher>();
        let fingerprint = self.get_zksig_circuit_fingerprint();

        ZKPublicKeyInfo {
            fingerprint,
            public_key_param,
        }
    }

    pub fn add_private_key(&mut self, private_key: SimplePsyPrivateKey<C::F>) -> QHashOut<C::F> {
        let public_key = private_key.get_public_key_for_fingerprint::<C::Hasher>(self.get_zksig_circuit_fingerprint());
        self.public_key_to_private_key_store.insert(public_key, private_key);
        public_key
    }
    pub fn get_public_keys(&self) -> Vec<QHashOut<C::F>> {
        self.public_key_to_private_key_store.keys().map(|x| *x).collect::<Vec<_>>()
    }
    pub fn zk_sign_for_private_key_value(
        &self,
        private_key_value: QHashOut<C::F>,
        sig_hash: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.circuit.prove_base(private_key_value, sig_hash)
    }
    pub fn zk_sign_for_public_key(&self, public_key: QHashOut<C::F>, sig_hash: QHashOut<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        if !self.public_key_to_private_key_store.contains_key(&public_key) {
            anyhow::bail!(
                "tried to sign with a public key ({}) which does not match any private keys in the store",
                public_key.to_string()
            );
        } else {
            let private_key = self.public_key_to_private_key_store.get(&public_key).unwrap().private_key;
            self.circuit.prove_base(private_key, sig_hash)
        }
    }

    pub fn contains_key(&self, public_key: QHashOut<C::F>) -> bool {
        self.public_key_to_private_key_store.contains_key(&public_key)
    }

    pub fn get_private_key(&self, public_key: QHashOut<C::F>) -> anyhow::Result<&SimplePsyPrivateKey<C::F>> {
        self.public_key_to_private_key_store
            .get(&public_key)
            .ok_or(anyhow::format_err!("public key {} not found", public_key.to_string()))
    }
}

#[cfg(test)]
mod tests {

    use plonky2::{hash::poseidon::PoseidonHash, plonk::config::PoseidonGoldilocksConfig};
    use psy_client_common::utils::debug_timer::DebugTimer;

    use super::*;

    #[test]
    fn test_zk_sign() -> anyhow::Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        let mut timer = DebugTimer::new("test_zk_sign");

        let mut mgr = SimplePsyZKSignatureManager::<C, D>::new();
        timer.lap("built circuit");
        let private_key = SimplePsyPrivateKey::new(QHashOut::rand());
        let expected_public_param = private_key.get_public_key_param::<PoseidonHash>();
        let expected_public_key = private_key.get_public_key_for_fingerprint::<PoseidonHash>(mgr.circuit.get_fingerprint());

        let public_key = mgr.add_private_key(private_key);
        assert_eq!(
            expected_public_key, public_key,
            "public key returned by the signature manager does not match the public key we computed"
        );

        let sig_hash = QHashOut::rand();

        timer.lap("started proving");
        let result = mgr.zk_sign_for_public_key(public_key, sig_hash)?;

        timer.lap("finished proving");
        let is_valid = mgr.verify_simple_zk_signature(public_key, expected_public_param, sig_hash, result);
        timer.lap("finished verifying signature");
        assert!(is_valid, "error verifying zk signature");
        Ok(())
    }
}
