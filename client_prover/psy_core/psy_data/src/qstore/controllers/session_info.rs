use plonky2::hash::hash_types::RichField;
use psy_client_common::{
    data::{alt::AltVerifierOnlyCircuitData, qhashout::QHashOut},
    ups::circuits::LocalCircuitId,
};
use psy_crypto::hash::merkle::core::MerkleProofCore;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct BasicCircuitInfo<F: RichField> {
    pub id: LocalCircuitId,
    pub fingerprint: QHashOut<F>,
    pub verifier_data: AltVerifierOnlyCircuitData<F>,
}

#[derive(Clone, Debug)]

pub struct SessionCircuitInfoStore<F: RichField> {
    registered_circuit_info: Vec<BasicCircuitInfo<F>>,
    circuit_id_to_info_index: hashbrown::HashMap<LocalCircuitId, usize>,
    fingerprint_to_info_index: hashbrown::HashMap<QHashOut<F>, usize>,

    circuit_whitelist_merkle_proof_map: hashbrown::HashMap<LocalCircuitId, MerkleProofCore<QHashOut<F>>>,
}

impl<F: RichField> SessionCircuitInfoStore<F> {
    pub fn new() -> Self {
        Self {
            registered_circuit_info: Vec::new(),
            circuit_id_to_info_index: hashbrown::HashMap::new(),
            fingerprint_to_info_index: hashbrown::HashMap::new(),
            circuit_whitelist_merkle_proof_map: hashbrown::HashMap::new(),
        }
    }
    pub fn register_whitelist_merkle_proof(&mut self, circuit_id: LocalCircuitId, whitelist_merkle_proof: MerkleProofCore<QHashOut<F>>) {
        if !self.circuit_whitelist_merkle_proof_map.contains_key(&circuit_id) {
            self.circuit_whitelist_merkle_proof_map.insert(circuit_id, whitelist_merkle_proof);
        } else {
            if !whitelist_merkle_proof.eq(self.circuit_whitelist_merkle_proof_map.get(&circuit_id).unwrap()) {
                panic!("inserted two different whitelist merkle proofs for circuit id {:?}", circuit_id);
            }
        }
    }
    pub fn get_whitelist_merkle_proof(&self, circuit_id: LocalCircuitId) -> anyhow::Result<&MerkleProofCore<QHashOut<F>>> {
        match self.circuit_whitelist_merkle_proof_map.get(&circuit_id) {
            Some(p) => Ok(p),
            None => anyhow::bail!("whitelist merkle proof not registered for circuit id {:?}", circuit_id),
        }
    }
    pub fn insert_info_item(&mut self, item: BasicCircuitInfo<F>) -> usize {
        if self.circuit_id_to_info_index.contains_key(&item.id) {
            let index = *self.circuit_id_to_info_index.get(&item.id).unwrap();
            if self.registered_circuit_info[index].eq(&item) {
                index
            } else {
                panic!("attempted to insert circuit info with different data for the same id: {:?}", item.id);
            }
        } else {
            let index = self.registered_circuit_info.len();

            self.circuit_id_to_info_index.insert(item.id, index);
            self.fingerprint_to_info_index.insert(item.fingerprint, index);

            self.registered_circuit_info.push(item);

            index
        }
    }
    pub fn add_basic_info_list(&mut self, list: Vec<BasicCircuitInfo<F>>) {
        self.circuit_id_to_info_index.reserve(list.len());
        list.into_iter().for_each(|x| {
            self.insert_info_item(x);
        });
    }
    pub fn register_circuit(&mut self, id: LocalCircuitId, fingerprint: QHashOut<F>, verifier_data: AltVerifierOnlyCircuitData<F>) {
        self.insert_info_item(BasicCircuitInfo {
            id,
            fingerprint,
            verifier_data,
        });
    }
    pub fn get_circuit_info_by_id(&self, id: LocalCircuitId) -> anyhow::Result<&BasicCircuitInfo<F>> {
        match self.circuit_id_to_info_index.get(&id) {
            Some(index) => Ok(&self.registered_circuit_info[*index]),
            None => anyhow::bail!("attempted to get info for circuit with id {:?}, which has not been registered", id),
        }
    }
    pub fn get_circuit_info_by_fingerprint(&self, fingerprint: QHashOut<F>) -> anyhow::Result<&BasicCircuitInfo<F>> {
        match self.fingerprint_to_info_index.get(&fingerprint) {
            Some(index) => Ok(&self.registered_circuit_info[*index]),
            None => anyhow::bail!(
                "attempted to get info for circuit with fingerprint {:?}, which has not been registered",
                fingerprint
            ),
        }
    }
}
