use std::collections::HashMap;

use parth_core::{data::hash::hash256::Hash256, pgoldilocks::QHashOut};
use parth_crypto::hash::sha256::CoreSha256Hasher;
use plonky2::{
    hash::hash_types::RichField,
    plonk::{
        circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_core::job::job_id::ProvingJobCircuitType;
use serde::{Deserialize, Serialize};


use super::{
    circuit_library::{CircuitInfoLibrary, CircuitInfoLibraryBuilder},
    simple_circuit_library::{SerializableSimpleCircuitLibrary, SimpleCircuitLibrary},
};

#[derive(Debug, Clone)]
pub struct GenericCircuitCommonDataLibrary<C: GenericConfig<D>, const D: usize> {
    pub common_data_items: Vec<CommonCircuitData<C::F, D>>,
    pub common_data_hashes: Vec<Hash256>,
    pub common_circuit_map: HashMap<ProvingJobCircuitType, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SerializedGenericCircuitCommonDataLibraryInfo {
    pub common_data_hashes: Vec<Hash256>,
    pub common_circuit_list: Vec<Vec<ProvingJobCircuitType>>,
}

impl<C: GenericConfig<D>, const D: usize> GenericCircuitCommonDataLibrary<C, D> {
    pub fn new() -> Self {
        Self {
            common_data_items: Vec::new(),
            common_data_hashes: Vec::new(),
            common_circuit_map: HashMap::new(),
        }
    }
    pub fn print_common(&self) {
        println!("\n=====================================");
        let list = self.to_serialized().common_circuit_list;
        self.common_data_items
            .iter()
            .zip(self.common_data_hashes.iter())
            .zip(list.iter())
            .for_each(|((common_data, common_data_hash), circuit_types)| {
                println!(
                    "\nCircuit Types: {:?}\nHash: {}\nCommon Data:\n{:?}\n",
                    circuit_types,
                    common_data_hash.to_hex_string(),
                    common_data
                );
                println!("\n=====================================");
            });
    }
    fn hash_common_circuit_data(common_data: &CommonCircuitData<C::F, D>) -> Hash256 {
        let cd_str = format!("CDV1_{:?}", common_data);
        CoreSha256Hasher::hash_bytes(cd_str.as_bytes())
    }
    pub fn insert_common_data(
        &mut self,
        circuit_type: ProvingJobCircuitType,
        common_data: CommonCircuitData<C::F, D>,
    ) {
        let new_hash = Self::hash_common_circuit_data(&common_data);
        tracing::debug!("Circuit verifier - circuit_type: {:?}, new_hash: {}", circuit_type, new_hash);
        match self.common_data_hashes.iter().position(|x| new_hash.eq(x)) {
            Some(ind) => {
                self.common_circuit_map.insert(circuit_type, ind);
            }
            None => {
                let new_ind = self.common_data_hashes.len();
                self.common_data_hashes.push(new_hash);
                self.common_data_items.push(common_data);
                self.common_circuit_map.insert(circuit_type, new_ind);
            }
        }
    }

    pub fn from_serialized(
        ser: &SerializedGenericCircuitCommonDataLibraryInfo,
        common_data_items: Vec<CommonCircuitData<C::F, D>>,
    ) -> anyhow::Result<Self> {
        if common_data_items.len() != ser.common_data_hashes.len() {
            anyhow::bail!("ser.common_data_hashes.len() != common_data_items.len() (ser.common_data_hashes.len() = {}), got {}",ser.common_data_hashes.len(),common_data_items.len());
        }
        if ser.common_circuit_list.len() != ser.common_data_hashes.len() {
            anyhow::bail!("ser.common_circuit_list.len() != ser.common_data_hashes.len() (ser.common_circuit_list.len() = {}), got {}",ser.common_circuit_list.len(),common_data_items.len());
        }

        for (cdata, expected_cdata_hash) in
            common_data_items.iter().zip(ser.common_data_hashes.iter())
        {
            if !Self::hash_common_circuit_data(cdata).eq(expected_cdata_hash) {
                anyhow::bail!("invalid common data hash in serialized data");
            }
        }

        let mut common_circuit_map = HashMap::new();

        ser.common_circuit_list
            .iter()
            .enumerate()
            .for_each(|(index, l)| {
                l.iter().for_each(|circuit_type| {
                    common_circuit_map.insert(*circuit_type, index);
                });
            });

        Ok(Self {
            common_data_items,
            common_data_hashes: ser.common_data_hashes.clone(),
            common_circuit_map,
        })
    }
    pub fn to_serialized(&self) -> SerializedGenericCircuitCommonDataLibraryInfo {
        let cdata_len = self.common_data_hashes.len();
        let mut common_circuit_list = vec![Vec::new(); cdata_len];
        self.common_circuit_map.iter().for_each(|(k, v)| {
            if *v < cdata_len {
                common_circuit_list[*v].push(*k);
            }
        });

        let result = SerializedGenericCircuitCommonDataLibraryInfo {
            common_data_hashes: self.common_data_hashes.clone(),
            common_circuit_list,
        };

        println!("Serialized: common_data_hashes.len(): {}", result.common_data_hashes.len());
        println!("Serialized: common_circuit_list.len(): {}", result.common_circuit_list.len());
        for (i, hash) in result.common_data_hashes.iter().enumerate() {
            println!("Hash {}: {}", i, hash.to_hex_string());
        }

        result
    }
    pub fn get_common_circuit_data_ref(
        &self,
        circuit_type: ProvingJobCircuitType,
    ) -> anyhow::Result<&CommonCircuitData<C::F, D>> {
        match self.common_circuit_map.get(&circuit_type) {
            Some(x) => Ok(&self.common_data_items[*x]),
            None => anyhow::bail!("no common data found for circuit type {:?}", circuit_type),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SerializedGenericCircuitVerifier<F: RichField> {
    pub library: SerializableSimpleCircuitLibrary<F>,
    pub common: SerializedGenericCircuitCommonDataLibraryInfo,
}

#[derive(Debug, Clone)]
pub struct GenericCircuitVerifier<C: GenericConfig<D>, const D: usize> {
    pub library: SimpleCircuitLibrary<C::F>,
    pub common: GenericCircuitCommonDataLibrary<C, D>,
}

impl<C: GenericConfig<D>, const D: usize> GenericCircuitVerifier<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new() -> Self {
        Self {
            library: SimpleCircuitLibrary::new(),
            common: GenericCircuitCommonDataLibrary::new(),
        }
    }
    pub fn from_serialized(
        ser: SerializedGenericCircuitVerifier<C::F>,
        common_data_items: Vec<CommonCircuitData<C::F, D>>,
    ) -> anyhow::Result<Self> {
        let library = SimpleCircuitLibrary::from_serialized(ser.library);
        let common =
            GenericCircuitCommonDataLibrary::from_serialized(&ser.common, common_data_items)?;

        Ok(Self { library, common })
    }
    pub fn to_serialized(&self) -> SerializedGenericCircuitVerifier<C::F> {
        let library = self.library.to_serialized();
        let common = self.common.to_serialized();

        SerializedGenericCircuitVerifier { library, common }
    }
    pub fn verify_proof_of_type(
        &self,
        circuit_type: ProvingJobCircuitType,
        proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<()>
    where
        C::Hasher: AlgebraicHasher<C::F>,
    {
        let cdata_ref = self.common.get_common_circuit_data_ref(circuit_type)?;
        self.library
            .verify_proof_of_type(circuit_type, cdata_ref, proof)?;
        Ok(())
    }

    pub fn register_circuit_triplet(
        &mut self,
        circuit_type: ProvingJobCircuitType,
        triplet: (
            &CommonCircuitData<C::F, D>,
            &VerifierOnlyCircuitData<C, D>,
            QHashOut<C::F>,
        ),
    ) {
        let (common_ref, v_ref, fingerprint) = triplet;

        self.library
            .register_circuit(circuit_type, fingerprint, v_ref.into());
        self.common
            .insert_common_data(circuit_type, common_ref.to_owned());
    }
}
