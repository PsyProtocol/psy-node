use hashbrown::HashMap;
use plonky2::plonk::{
    circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
    config::{AlgebraicHasher, GenericConfig},
    proof::ProofWithPublicInputs,
};
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::signature::zk::wallet::SimplePrivateKey;

use crate::circuits::{
    traits::qstandard::QStandardCircuit,
    zk_signature::{fixed_public_key::ZKSignatureCircuitSimpleFixedPublicKey, inner::ZKSignatureCircuitInner},
    zk_signature_wrapper::ZKSignatureWrapperCircuit,
};

#[derive(Debug)]
pub struct SimpleZKSignatureWalletKey<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub circuit_fingerprint_public_key: QHashOut<C::F>,
    pub hash_public_key: QHashOut<C::F>,
    pub fixed_circuit: ZKSignatureCircuitSimpleFixedPublicKey<C, D>,
}
pub trait ZKSignatureBasicWalletProvider<C: GenericConfig<D> + 'static, const D: usize> {
    fn zk_sign(&self, private_key: QHashOut<C::F>, action_hash: QHashOut<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
    fn get_public_keys(&self) -> Vec<QHashOut<C::F>>;
    fn get_hash_public_keys(&self) -> Vec<QHashOut<C::F>>;
    fn add_hash_public_key(&mut self, hash_public_key: QHashOut<C::F>) -> QHashOut<C::F>;
    /// Remove the circuit fingerprint returned by `add_hash_public_key`.
    fn remove_public_key(&mut self, public_key: QHashOut<C::F>);
    fn contains_public_key(&self, public_key: QHashOut<C::F>) -> bool;
    fn contains_hash_public_key(&self, hash_public_key: QHashOut<C::F>) -> bool;
    fn get_public_key_from_hash_public_key(&self, hash_public_key: QHashOut<C::F>) -> Option<QHashOut<C::F>>;
    fn clear(&mut self);
}
pub trait ZKSignatureWalletProvider<C: GenericConfig<D> + 'static, const D: usize>: ZKSignatureBasicWalletProvider<C, D> {
    fn sign(&self, public_key: QHashOut<C::F>, action_hash: QHashOut<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
    fn sign_by_hash_public_key(
        &self,
        hash_public_key: QHashOut<C::F>,
        action_hash: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;
    fn add_private_key(&mut self, private_key: QHashOut<C::F>) -> QHashOut<C::F>;
}

pub struct SimpleZKSignatureWallet<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub inner_circuit: ZKSignatureCircuitInner<C, D>,
    pub wrapper_circuit: ZKSignatureWrapperCircuit<C, D>,
    pub key_map: HashMap<QHashOut<C::F>, SimpleZKSignatureWalletKey<C, D>>,
    pub hash_public_key_to_fingerprint: HashMap<QHashOut<C::F>, QHashOut<C::F>>,
}

impl<C: GenericConfig<D> + 'static, const D: usize> Clone for SimpleZKSignatureWallet<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn clone(&self) -> Self {
        let mut key_map: HashMap<QHashOut<C::F>, SimpleZKSignatureWalletKey<C, D>> = HashMap::new();
        let hash_public_key_to_fingerprint = self.hash_public_key_to_fingerprint.clone();
        let inner_circuit = self.inner_circuit.clone();
        let wrapper_circuit = self.wrapper_circuit.clone();
        self.key_map.iter().for_each(|(k, v)| {
            key_map.insert(
                *k,
                SimpleZKSignatureWalletKey {
                    circuit_fingerprint_public_key: v.circuit_fingerprint_public_key,
                    hash_public_key: v.hash_public_key,
                    fixed_circuit: ZKSignatureCircuitSimpleFixedPublicKey::<C, D>::new_from_isc(&inner_circuit, v.hash_public_key),
                },
            );
        });

        Self {
            key_map,
            hash_public_key_to_fingerprint,
            inner_circuit,
            wrapper_circuit,
        }
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize> SimpleZKSignatureWallet<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new() -> Self {
        let inner_circuit = ZKSignatureCircuitInner::new();
        let fixed_circuit = ZKSignatureCircuitSimpleFixedPublicKey::new_from_isc(&inner_circuit, QHashOut::from_values(1337, 1337, 1337, 1337));
        let wrapper_circuit = ZKSignatureWrapperCircuit::new_from_common(
            &fixed_circuit.get_common_circuit_data_ref(),
            fixed_circuit.get_verifier_config_ref().constants_sigmas_cap.height(),
        );

        Self {
            inner_circuit,
            wrapper_circuit,
            key_map: HashMap::new(),
            hash_public_key_to_fingerprint: HashMap::new(),
        }
    }
    pub fn get_fingerprint_public_key_for_private_key(&self, private_key: QHashOut<C::F>) -> QHashOut<C::F> {
        let pk = SimplePrivateKey::new(private_key);
        let hash_public_key = pk.get_public_key::<C::Hasher>();
        let fixed_circuit = ZKSignatureCircuitSimpleFixedPublicKey::new_from_isc(&self.inner_circuit, hash_public_key);
        fixed_circuit.get_fingerprint()
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> ZKSignatureBasicWalletProvider<C, D> for SimpleZKSignatureWallet<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn zk_sign(&self, private_key: QHashOut<C::F>, action_hash: QHashOut<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let pk = SimplePrivateKey::new(private_key);
        let hash_public_key = pk.get_public_key::<C::Hasher>();
        let fingeprint_result = self.hash_public_key_to_fingerprint.get(&hash_public_key);
        if fingeprint_result.is_some() {
            let key_result = self.key_map.get(fingeprint_result.unwrap());
            if key_result.is_some() {
                let key = key_result.unwrap();
                let inner_proof = self.inner_circuit.prove_base(private_key, action_hash)?;
                let fixed_proof = key.fixed_circuit.prove_base(&inner_proof)?;
                self.wrapper_circuit.prove_base(&fixed_proof, key.fixed_circuit.get_verifier_config_ref())
            } else {
                anyhow::bail!("Key not found");
            }
        } else {
            let fixed_circuit = ZKSignatureCircuitSimpleFixedPublicKey::new_from_isc(&self.inner_circuit, hash_public_key);
            let circuit_fingerprint_public_key = fixed_circuit.get_fingerprint();
            let key = SimpleZKSignatureWalletKey {
                circuit_fingerprint_public_key,
                hash_public_key,
                fixed_circuit,
            };
            let inner_proof = self.inner_circuit.prove_base(private_key, action_hash)?;
            let fixed_proof = key.fixed_circuit.prove_base(&inner_proof)?;
            self.wrapper_circuit.prove_base(&fixed_proof, key.fixed_circuit.get_verifier_config_ref())
        }
    }

    fn get_public_keys(&self) -> Vec<QHashOut<C::F>> {
        self.key_map.keys().cloned().collect()
    }

    fn get_hash_public_keys(&self) -> Vec<QHashOut<C::F>> {
        self.hash_public_key_to_fingerprint.keys().cloned().collect()
    }

    fn add_hash_public_key(&mut self, hash_public_key: QHashOut<C::F>) -> QHashOut<C::F> {
        if self.hash_public_key_to_fingerprint.contains_key(&hash_public_key) {
            return self.hash_public_key_to_fingerprint[&hash_public_key];
        }

        let fixed_circuit = ZKSignatureCircuitSimpleFixedPublicKey::new_from_isc(&self.inner_circuit, hash_public_key);
        let circuit_fingerprint_public_key = fixed_circuit.get_fingerprint();
        let key = SimpleZKSignatureWalletKey {
            circuit_fingerprint_public_key,
            hash_public_key,
            fixed_circuit,
        };
        self.key_map.insert(circuit_fingerprint_public_key, key);
        self.hash_public_key_to_fingerprint
            .insert(hash_public_key, circuit_fingerprint_public_key);

        circuit_fingerprint_public_key
    }

    fn remove_public_key(&mut self, public_key: QHashOut<C::F>) {
        if let Some(key) = self.key_map.remove(&public_key) {
            self.hash_public_key_to_fingerprint.remove(&key.hash_public_key);
        }
    }

    fn contains_public_key(&self, public_key: QHashOut<C::F>) -> bool {
        self.key_map.contains_key(&public_key)
    }

    fn contains_hash_public_key(&self, hash_public_key: QHashOut<C::F>) -> bool {
        self.hash_public_key_to_fingerprint.contains_key(&hash_public_key)
    }

    fn get_public_key_from_hash_public_key(&self, hash_public_key: QHashOut<C::F>) -> Option<QHashOut<C::F>> {
        let result = self.hash_public_key_to_fingerprint.get(&hash_public_key);
        if result.is_some() {
            Some(*result.unwrap())
        } else {
            None
        }
    }

    fn clear(&mut self) {
        self.hash_public_key_to_fingerprint.clear();
        self.key_map.clear();
    }
}

pub struct MemoryZKSignatureWallet<C: GenericConfig<D> + 'static, const D: usize, BP: ZKSignatureBasicWalletProvider<C, D>>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub basic_wallet: BP,
    fingerprint_public_key_to_private_key: HashMap<QHashOut<C::F>, QHashOut<C::F>>,
}

impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D> for MemoryZKSignatureWallet<C, D, SimpleZKSignatureWallet<C, D>>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        self.basic_wallet.wrapper_circuit.get_fingerprint()
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        self.basic_wallet.wrapper_circuit.get_verifier_config_ref()
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        self.basic_wallet.wrapper_circuit.get_common_circuit_data_ref()
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize, BP: ZKSignatureBasicWalletProvider<C, D> + Clone> Clone for MemoryZKSignatureWallet<C, D, BP>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn clone(&self) -> Self {
        Self {
            basic_wallet: self.basic_wallet.clone(),
            fingerprint_public_key_to_private_key: self.fingerprint_public_key_to_private_key.clone(),
        }
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize, BP: ZKSignatureBasicWalletProvider<C, D>> MemoryZKSignatureWallet<C, D, BP>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(basic_wallet: BP) -> Self {
        Self {
            basic_wallet,
            fingerprint_public_key_to_private_key: HashMap::new(),
        }
    }
    pub fn new_memory() -> MemoryZKSignatureWallet<C, D, SimpleZKSignatureWallet<C, D>> {
        MemoryZKSignatureWallet::<C, D, SimpleZKSignatureWallet<C, D>>::new(SimpleZKSignatureWallet::new())
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize, BP: ZKSignatureBasicWalletProvider<C, D>> ZKSignatureBasicWalletProvider<C, D>
    for MemoryZKSignatureWallet<C, D, BP>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn zk_sign(&self, private_key: QHashOut<C::F>, action_hash: QHashOut<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.basic_wallet.zk_sign(private_key, action_hash)
    }

    fn get_public_keys(&self) -> Vec<QHashOut<C::F>> {
        self.basic_wallet.get_public_keys()
    }

    fn get_hash_public_keys(&self) -> Vec<QHashOut<C::F>> {
        self.basic_wallet.get_hash_public_keys()
    }

    fn add_hash_public_key(&mut self, hash_public_key: QHashOut<C::F>) -> QHashOut<C::F> {
        self.basic_wallet.add_hash_public_key(hash_public_key)
    }

    fn remove_public_key(&mut self, public_key: QHashOut<C::F>) {
        self.fingerprint_public_key_to_private_key.remove(&public_key);
        self.basic_wallet.remove_public_key(public_key)
    }

    fn contains_public_key(&self, public_key: QHashOut<C::F>) -> bool {
        self.basic_wallet.contains_public_key(public_key)
    }

    fn contains_hash_public_key(&self, hash_public_key: QHashOut<C::F>) -> bool {
        self.basic_wallet.contains_hash_public_key(hash_public_key)
    }

    fn get_public_key_from_hash_public_key(&self, hash_public_key: QHashOut<C::F>) -> Option<QHashOut<C::F>> {
        self.basic_wallet.get_public_key_from_hash_public_key(hash_public_key)
    }

    fn clear(&mut self) {
        self.fingerprint_public_key_to_private_key.clear();
        self.basic_wallet.clear();
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize, BP: ZKSignatureBasicWalletProvider<C, D>> ZKSignatureWalletProvider<C, D>
    for MemoryZKSignatureWallet<C, D, BP>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn sign(&self, public_key: QHashOut<C::F>, action_hash: QHashOut<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let private_key = self.fingerprint_public_key_to_private_key.get(&public_key);
        if private_key.is_some() {
            self.zk_sign(*private_key.unwrap(), action_hash)
        } else {
            anyhow::bail!("Private key not found")
        }
    }

    fn add_private_key(&mut self, private_key: QHashOut<C::F>) -> QHashOut<C::F> {
        let pk = SimplePrivateKey::new(private_key);
        let hash_public_key = pk.get_public_key::<C::Hasher>();
        let public_key = self.basic_wallet.add_hash_public_key(hash_public_key);
        self.fingerprint_public_key_to_private_key.insert(public_key, private_key);
        public_key
    }

    fn sign_by_hash_public_key(
        &self,
        hash_public_key: QHashOut<C::F>,
        action_hash: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let public_key_result = self.get_public_key_from_hash_public_key(hash_public_key);
        if public_key_result.is_some() {
            self.sign(public_key_result.unwrap(), action_hash)
        } else {
            anyhow::bail!("Public key not found")
        }
    }
}

#[cfg(test)]
mod tests {
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    use super::*;

    #[test]
    fn remove_public_key_clears_private_key_and_both_public_key_maps() {
        type C = PoseidonGoldilocksConfig;
        let mut wallet = MemoryZKSignatureWallet::<C, 2, SimpleZKSignatureWallet<C, 2>>::new_memory();
        let private_key = QHashOut::from_values(1, 2, 3, 4);
        let hash_public_key = SimplePrivateKey::new(private_key).get_public_key::<<C as GenericConfig<2>>::Hasher>();
        let public_key = wallet.add_private_key(private_key);
        let other_private_key = QHashOut::from_values(5, 6, 7, 8);
        let other_hash_public_key = SimplePrivateKey::new(other_private_key).get_public_key::<<C as GenericConfig<2>>::Hasher>();
        let other_public_key = wallet.add_private_key(other_private_key);
        assert_ne!(public_key, hash_public_key);
        assert!(wallet.contains_public_key(public_key));
        assert!(wallet.contains_hash_public_key(hash_public_key));

        // The removal API accepts fingerprints, not hash public keys.
        wallet.remove_public_key(hash_public_key);
        assert!(wallet.contains_public_key(public_key));
        assert!(wallet.contains_hash_public_key(hash_public_key));
        assert!(wallet.fingerprint_public_key_to_private_key.contains_key(&public_key));

        wallet.remove_public_key(public_key);
        assert!(!wallet.contains_public_key(public_key));
        assert!(!wallet.contains_hash_public_key(hash_public_key));
        assert_eq!(wallet.get_public_key_from_hash_public_key(hash_public_key), None);
        assert!(!wallet.basic_wallet.key_map.contains_key(&public_key));
        assert!(!wallet.basic_wallet.hash_public_key_to_fingerprint.contains_key(&hash_public_key));
        assert!(!wallet.fingerprint_public_key_to_private_key.contains_key(&public_key));
        assert!(wallet.sign(public_key, hash_public_key).is_err());
        assert!(wallet.sign_by_hash_public_key(hash_public_key, hash_public_key).is_err());

        // Repeated removal is harmless and leaves the other account intact.
        wallet.remove_public_key(public_key);
        assert_eq!(wallet.get_public_keys(), vec![other_public_key]);
        assert_eq!(wallet.get_hash_public_keys(), vec![other_hash_public_key]);
        assert_eq!(wallet.fingerprint_public_key_to_private_key.get(&other_public_key), Some(&other_private_key));

        assert_eq!(wallet.add_private_key(private_key), public_key);
        assert!(wallet.contains_public_key(public_key));
        assert!(wallet.contains_hash_public_key(hash_public_key));
        assert_eq!(wallet.get_public_key_from_hash_public_key(hash_public_key), Some(public_key));
        assert_eq!(wallet.fingerprint_public_key_to_private_key.get(&public_key), Some(&private_key));
    }
}
