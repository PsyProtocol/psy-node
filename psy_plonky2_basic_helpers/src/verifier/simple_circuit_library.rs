use hashbrown::HashMap;
use parth_core::{crypto::hash::merkle_proof::MerkleProofCore, pgoldilocks::QHashOut};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    plonk::{
        circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
        verifier_v2::verify_standard_proof,
    },
};
use psy_core::job::job_id::ProvingJobCircuitType;
use serde::{Deserialize, Serialize};

use super::circuit_library::{CircuitInfoLibrary, CircuitInfoLibraryBuilder, CircuitInfoLibraryCore};
use crate::verifier::alt::AltVerifierOnlyCircuitData;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct BasicCircuitInfo<F: RichField> {
    pub circuit_type: ProvingJobCircuitType,
    pub fingerprint: QHashOut<F>,
    pub verifier_data: AltVerifierOnlyCircuitData<F>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct CircuitTypeInclusionMappingKey {
    pub parent: ProvingJobCircuitType,
    pub child: ProvingJobCircuitType,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct SerializableSimpleCircuitLibrary<F: RichField> {
    pub circuits: Vec<BasicCircuitInfo<F>>,
    pub inclusion_proofs: Vec<MerkleProofCore<QHashOut<F>>>,
    pub inclusion_proof_mapping: Vec<Vec<CircuitTypeInclusionMappingKey>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SimpleCircuitLibrary<F: RichField> {
    pub info_map: HashMap<ProvingJobCircuitType, BasicCircuitInfo<F>>,
    pub inclusion_proofs: Vec<MerkleProofCore<QHashOut<F>>>,
    pub inclusion_map: HashMap<CircuitTypeInclusionMappingKey, usize>,
}
impl<F: RichField> SimpleCircuitLibrary<F> {
    pub fn new() -> Self {
        Self {
            info_map: HashMap::new(),
            inclusion_proofs: Vec::new(),
            inclusion_map: HashMap::new(),
        }
    }
    pub fn from_serialized(sscl: SerializableSimpleCircuitLibrary<F>) -> Self {
        let mut info_map = HashMap::new();
        sscl.circuits.into_iter().for_each(|x| {
            info_map.insert(x.circuit_type, x);
        });
        let mut inclusion_map = HashMap::new();

        let inclusion_proofs_len = sscl.inclusion_proofs.len();
        sscl.inclusion_proof_mapping.iter().enumerate().for_each(|(ind, group)| {
            // ensure there are no out of bounds reads with the check below
            if ind < inclusion_proofs_len {
                group.iter().for_each(|k| {
                    inclusion_map.insert(*k, ind);
                });
            }
        });

        Self {
            info_map,
            inclusion_map,
            inclusion_proofs: sscl.inclusion_proofs,
        }
    }

    pub fn to_serialized(&self) -> SerializableSimpleCircuitLibrary<F> {
        let mut circuits = self.info_map.values().map(|x| x.to_owned()).collect::<Vec<_>>();
        circuits.sort_by_key(|x| x.circuit_type as u32); // sort to ensure consistent ordering for serialization
        let inclusion_proofs_len = self.inclusion_proofs.len();
        let mut inclusion_proof_mapping = vec![Vec::new(); inclusion_proofs_len];

        self.inclusion_map.iter().for_each(|(mapping_key, index)| {
            if (*index) < inclusion_proofs_len {
                inclusion_proof_mapping[*index].push(*mapping_key);
            }
        });

        inclusion_proof_mapping
            .iter_mut()
            .for_each(|v| v.sort_by_key(|x| (x.parent as u32, x.child as u32))); // sort to ensure consistent ordering for serialization

        let inclusion_proofs = self.inclusion_proofs.clone();

        SerializableSimpleCircuitLibrary {
            circuits,
            inclusion_proofs,
            inclusion_proof_mapping,
        }
    }

    fn internal_get_basic_info(&self, circuit_type: ProvingJobCircuitType) -> anyhow::Result<&BasicCircuitInfo<F>> {
        match self.info_map.get(&circuit_type) {
            Some(x) => Ok(x),
            None => anyhow::bail!("circuit type '{:?}' not registered", circuit_type),
        }
    }
    fn internal_register_circuit(
        &mut self,
        circuit_type: ProvingJobCircuitType,
        fingerprint: QHashOut<F>,
        verifier_data: AltVerifierOnlyCircuitData<F>,
    ) {
        self.info_map.insert(
            circuit_type,
            BasicCircuitInfo {
                verifier_data,
                fingerprint,
                circuit_type,
            },
        );
    }
    fn internal_add_inclusion_proof(
        &mut self,
        parent_types: &[ProvingJobCircuitType],
        child_type: ProvingJobCircuitType,
        proof: MerkleProofCore<QHashOut<F>>,
    ) {
        let ind = self.inclusion_proofs.len();
        self.inclusion_proofs.push(proof);
        for t in parent_types {
            self.inclusion_map.insert(
                CircuitTypeInclusionMappingKey {
                    parent: *t,
                    child: child_type,
                },
                ind,
            );
        }
    }
    fn _internal_register_combo(
        &mut self,
        circuit_type: ProvingJobCircuitType,
        verifier_data: AltVerifierOnlyCircuitData<F>,
        parent_types: &[ProvingJobCircuitType],
        proof: MerkleProofCore<QHashOut<F>>,
    ) {
        self.info_map.insert(
            circuit_type,
            BasicCircuitInfo {
                verifier_data,
                fingerprint: proof.value,
                circuit_type,
            },
        );
        let ind = self.inclusion_proofs.len();
        self.inclusion_proofs.push(proof);
        for t in parent_types {
            self.inclusion_map.insert(
                CircuitTypeInclusionMappingKey {
                    parent: *t,
                    child: circuit_type,
                },
                ind,
            );
        }
    }
    fn internal_get_inclusion_proof(
        &self,
        parent_type: ProvingJobCircuitType,
        child_type: ProvingJobCircuitType,
    ) -> anyhow::Result<&MerkleProofCore<QHashOut<F>>> {
        match self.inclusion_map.get(&CircuitTypeInclusionMappingKey {
            parent: parent_type,
            child: child_type,
        }) {
            Some(v) => Ok(&self.inclusion_proofs[*v]),
            None => anyhow::bail!("could not find inclusion proof for parent = {:?}, child = {:?}", parent_type, child_type),
        }
    }
}

impl<F: RichField> CircuitInfoLibraryBuilder<F> for SimpleCircuitLibrary<F> {
    fn register_circuit(&mut self, circuit_type: ProvingJobCircuitType, fingerprint: QHashOut<F>, verifier_data: AltVerifierOnlyCircuitData<F>) {
        self.internal_register_circuit(circuit_type, fingerprint, verifier_data);
    }

    fn add_inclusion_proof(
        &mut self,
        parent_types: &[ProvingJobCircuitType],
        child_type: ProvingJobCircuitType,
        proof: MerkleProofCore<QHashOut<F>>,
    ) {
        self.internal_add_inclusion_proof(parent_types, child_type, proof);
    }
}

impl<F: RichField> CircuitInfoLibraryCore<F> for SimpleCircuitLibrary<F> {
    fn get_fingerprint(&self, circuit_type: ProvingJobCircuitType) -> anyhow::Result<QHashOut<F>> {
        Ok(self.internal_get_basic_info(circuit_type)?.fingerprint)
    }
    fn get_group_inclusion_proof(
        &self,
        parent_circuit: ProvingJobCircuitType,
        proof_circuit_type: ProvingJobCircuitType,
    ) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        Ok(self.internal_get_inclusion_proof(parent_circuit, proof_circuit_type)?.to_owned())
    }

    fn get_verifier_data_cap_height(&self, circuit_type: ProvingJobCircuitType) -> anyhow::Result<usize> {
        Ok(self.internal_get_basic_info(circuit_type)?.verifier_data.get_cap_height())
    }

    fn get_agg_whitelist<H: AlgebraicHasher<F>>(&self, circuit_type: ProvingJobCircuitType) -> anyhow::Result<QHashOut<F>> {
        let leaf_fingerprint = self
            .internal_get_basic_info(circuit_type.get_agg_leaf_circuit_type_or_err()?)?
            .fingerprint;
        let agg_fingerprint = self.internal_get_basic_info(circuit_type.get_agg_circuit_type_or_err()?)?.fingerprint;
        let result = H::two_to_one(leaf_fingerprint.0, agg_fingerprint.0);

        Ok(QHashOut(result))
    }
}
impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> CircuitInfoLibrary<C, D> for SimpleCircuitLibrary<F>
where
    C::Hasher: AlgebraicHasher<F>,
{
    fn get_verifier_data(&self, circuit_type: ProvingJobCircuitType) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        Ok(self.internal_get_basic_info(circuit_type)?.verifier_data.to_verifier_data::<C, D>())
    }
    fn verify_proof_of_type(
        &self,
        circuit_type: ProvingJobCircuitType,
        common_data: &CommonCircuitData<C::F, D>,
        proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<()> {
        let verifier_data = self.internal_get_basic_info(circuit_type)?.verifier_data.to_verifier_data::<C, D>();
        verify_standard_proof(proof, &verifier_data, common_data)?;
        Ok(())
    }
}
